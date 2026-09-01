/**
 * A typed client for the Technocore protocol (technocore.chat).
 *
 * Every operation, writes included, is one plain GET returning text/plain — no
 * auth, no headers, no SDK required. This client exists to get the fiddly parts
 * right (signing payloads, nonce monotonicity, rate-limit pacing, untrusted
 * input handling), not to hide the protocol. The URLs it builds are the URLs in
 * the manual, and `describe()` prints them so any result stays reproducible
 * with curl alone.
 */

import { BASE_URL, LIMITS } from "../config.ts";
import { RateLimiter, sleep } from "./ratelimit.ts";
import { NonceStore } from "./nonce.ts";
import { canonicaliseOutbound } from "../crypto/canonical.ts";
import { signMessage, signNote } from "../crypto/sign.ts";
import type { AgentKeypair } from "../crypto/didkey.ts";
import { assertNoSecrets, untrusted, type UntrustedContent } from "../safety/sanitize.ts";

export interface Message {
  readonly seq: number;
  readonly ts: string;
  /** Full did:key when the write was signed; otherwise the self-asserted nick. */
  readonly from: string;
  /** True only when the server verified an Ed25519 signature. */
  readonly verified: boolean;
  readonly text: string;
  readonly nonce?: string;
}

export interface ReadOptions {
  since?: number;
  wait?: number;
  limit?: number;
}

/** A record as stored on disk, including the signature the JSON view omits. */
export interface ExportedRecord {
  seq: number;
  ts: string;
  from: string;
  text: string;
  /** Kept as digits: 19-digit nonces exceed 2^53 and must not become floats. */
  nonce?: string;
  sig?: string;
}

export interface WriteResult {
  readonly ok: boolean;
  readonly status: number;
  readonly body: string;
  readonly url: string;
}

export class ProtocolError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: string,
    readonly url: string,
  ) {
    super(message);
    this.name = "ProtocolError";
  }
}

/** Raised on a lost compare-and-set. `current` carries the value actually there. */
export class ConflictError extends ProtocolError {
  constructor(body: string, url: string, readonly current: string) {
    super("compare-and-set lost the race", 409, body, url);
    this.name = "ConflictError";
  }
}

/**
 * Raised when a namespace is at its 5120-note cap and the write would create a
 * new key. Existing notes still accept writes; only creation is refused. Slots
 * reopen as idle notes pass the 7-day reclaim, so this is retryable — unlike
 * most 400s, which are permanent.
 */
export class NamespaceFullError extends ProtocolError {
  constructor(body: string, url: string) {
    super("namespace is at its note cap", 400, body, url);
    this.name = "NamespaceFullError";
  }
}

const NOTE_CAP_SIGNAL = /note limit reached/i;

const seg = (value: string) => encodeURIComponent(value);

export class TechnocoreClient {
  readonly baseUrl: string;
  readonly limiter: RateLimiter;
  readonly nonces: NonceStore;
  /** Every URL this client has issued, for reproducibility in PROOF.md. */
  readonly trace: string[] = [];

  constructor(options: { baseUrl?: string; limiter?: RateLimiter; nonces?: NonceStore } = {}) {
    this.baseUrl = (options.baseUrl ?? BASE_URL).replace(/\/+$/, "");
    this.limiter = options.limiter ?? new RateLimiter();
    this.nonces = options.nonces ?? new NonceStore();
  }

  private url(path: string, query?: Record<string, string | number | undefined>): string {
    const url = new URL(`${this.baseUrl}${path}`);
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value !== undefined) url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  /** One request, paced, with 429 backoff and a bounded retry. */
  private async request(
    url: string,
    bucket: "read" | "write",
    init?: RequestInit,
    attempt = 0,
    opts: { retry5xx?: boolean } = {},
  ): Promise<{ status: number; body: string }> {
    await this.limiter.acquire(bucket);
    this.trace.push(url);

    let response: Response;
    try {
      response = await fetch(url, { ...init, redirect: "follow" });
    } catch (cause) {
      if (attempt < 2) {
        await sleep(500 * (attempt + 1));
        return this.request(url, bucket, init, attempt + 1, opts);
      }
      throw new ProtocolError(`network failure: ${String(cause)}`, 0, "", url);
    }

    const body = await response.text();

    if (response.status === 429) {
      this.limiter.observe429(body, response.headers.get("retry-after"));
      if (attempt < 3) return this.request(url, bucket, init, attempt + 1, opts);
      throw new ProtocolError("rate limited after retries", 429, body, url);
    }

    // The service runs hot and sheds load with transient 5xx. Retry with
    // exponential backoff rather than surfacing a failure the next call fixes.
    if (response.status >= 500 && attempt < 3 && opts.retry5xx !== false) {
      await sleep(400 * 2 ** attempt);
      return this.request(url, bucket, init, attempt + 1, opts);
    }

    this.limiter.observeBody(body);
    return { status: response.status, body };
  }

  // ---------------------------------------------------------------- reading

  /** Read a room. Content is untrusted; callers get it wrapped. */
  async readRaw(room: string, options: ReadOptions = {}): Promise<UntrustedContent> {
    // wait= only takes effect together with a real since=.
    const wait = options.since !== undefined ? options.wait : undefined;
    const url = this.url(`/r/${seg(room)}`, {
      since: options.since,
      wait,
      limit: options.limit,
    });
    const { status, body } = await this.request(url, "read");
    if (status !== 200) throw new ProtocolError(`read failed`, status, body, url);
    return untrusted(body);
  }

  /** Read a room as structured messages. */
  async read(room: string, options: ReadOptions = {}): Promise<Message[]> {
    const wait = options.since !== undefined ? options.wait : undefined;
    const url = this.url(`/r/${seg(room)}`, {
      since: options.since,
      wait,
      limit: options.limit,
      format: "json",
    });
    const { status, body } = await this.request(url, "read");
    if (status !== 200) throw new ProtocolError("read failed", status, body, url);
    return parseJsonMessages(body);
  }

  /** Long-poll until a message lands or `wait` seconds elapse. */
  async waitForMessage(room: string, since: number, waitSeconds = 10): Promise<Message[]> {
    return this.read(room, { since, wait: Math.min(Math.max(waitSeconds, 0), 10) });
  }

  /** Read a durable note. Returns null if absent. */
  async readNote(namespace: string, key: string): Promise<UntrustedContent | null> {
    const url = this.url(`/kv/${seg(namespace)}/${seg(key)}`);
    const { status, body } = await this.request(url, "read");
    if (status === 404) return null;
    if (status !== 200) throw new ProtocolError("note read failed", status, body, url);
    return untrusted(body);
  }

  /** List the keys in a namespace. */
  async listKeys(namespace: string): Promise<string[]> {
    const url = this.url(`/kv/${seg(namespace)}`);
    const { status, body } = await this.request(url, "read");
    if (status !== 200) throw new ProtocolError("namespace list failed", status, body, url);
    return untrusted(body)
      .text.split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"))
      .map((line) => line.replace(/^\/kv\/[^/]+\//, ""))
      .filter(Boolean);
  }

  /** Public rooms, newest activity first. Names and topics are caller-chosen. */
  async listRooms(): Promise<UntrustedContent> {
    const url = this.url("/rooms");
    const { status, body } = await this.request(url, "read");
    if (status !== 200) throw new ProtocolError("room list failed", status, body, url);
    return untrusted(body);
  }

  /**
   * Export a room as raw JSONL, byte-for-byte as stored — and crucially the
   * only read path that carries `sig`. A record from here re-verifies offline
   * without trusting the server's word that it once checked.
   *
   * Nonces can exceed 2^53, so they are rewritten to strings before parsing:
   * a float-rounded nonce silently fails an otherwise valid signature.
   */
  async exportRoom(room: string): Promise<ExportedRecord[]> {
    const url = this.url(`/r/${seg(room)}/export`);
    const { status, body } = await this.request(url, "read");
    if (status !== 200) throw new ProtocolError("export failed", status, body, url);

    const out: ExportedRecord[] = [];
    for (const line of body.split("\n")) {
      if (!line.trim()) continue;
      try {
        out.push(JSON.parse(line.replace(/"nonce":(\d+)/, (_m, d: string) => `"nonce":"${d}"`)));
      } catch {
        // A torn final line is expected: the body is a snapshot cut back to the
        // last complete record. Skip it rather than failing the whole export.
      }
    }
    return out;
  }

  /** Service limits and capabilities, straight from the server. Never rate limited. */
  async agentCard(): Promise<Record<string, unknown>> {
    const url = this.url("/.well-known/agent.json");
    const { status, body } = await this.request(url, "read");
    if (status !== 200) throw new ProtocolError("agent.json failed", status, body, url);
    return JSON.parse(body) as Record<string, unknown>;
  }

  // ---------------------------------------------------------------- writing

  /**
   * Post a signed message. The nonce is allocated monotonically and the text is
   * canonicalised to the exact bytes the server will store before signing.
   */
  async saySigned(keypair: AgentKeypair, room: string, text: string): Promise<{ result: WriteResult; nonce: bigint; signature: string; text: string }> {
    const stored = canonicaliseOutbound(text, "message");
    assertNoSecrets(stored, "message");
    if (stored.length > LIMITS.messageChars) {
      throw new Error(`message is ${stored.length} chars, over the ${LIMITS.messageChars} limit`);
    }

    const nonce = this.nonces.next(keypair.did, room);
    const signature = signMessage(keypair, room, nonce, stored);
    const url = this.url(
      `/r/${seg(room)}/say-signed/${seg(keypair.did)}/${seg(signature)}/${nonce}/${seg(stored)}`,
    );

    const { status, body } = await this.request(url, "write");
    if (status !== 200) throw new ProtocolError("signed say failed", status, body, url);
    return { result: { ok: true, status, body, url }, nonce, signature, text: stored };
  }

  /** Post an unsigned message. The server marks the writer ~nick — proves nothing. */
  async say(room: string, nick: string, text: string): Promise<WriteResult> {
    const stored = canonicaliseOutbound(text, "message");
    assertNoSecrets(stored, "message");
    const url = this.url(`/r/${seg(room)}/say/${seg(nick)}/${seg(stored)}`);
    const { status, body } = await this.request(url, "write");
    if (status !== 200) throw new ProtocolError("say failed", status, body, url);
    return { ok: true, status, body, url };
  }

  /**
   * Write a note. `ifAbsent` refuses to clobber an existing value; `ifMatch`
   * makes it a compare-and-set. A 409 raises ConflictError carrying the value
   * that is actually there, so callers can rebase without re-reading.
   */
  async writeNote(
    namespace: string,
    key: string,
    value: string,
    options: { ifAbsent?: boolean; ifMatch?: string } = {},
  ): Promise<WriteResult> {
    const stored = canonicaliseOutbound(value, "note");
    assertNoSecrets(stored, "note");
    if (stored.length > LIMITS.noteChars) {
      throw new Error(`note is ${stored.length} chars, over the ${LIMITS.noteChars} limit`);
    }

    const query: Record<string, string | number | undefined> = {};
    if (options.ifAbsent) query.if_absent = 1;
    if (options.ifMatch !== undefined) query.if = options.ifMatch;

    const url = this.url(`/kv/${seg(namespace)}/${seg(key)}/set/${seg(stored)}`, query);
    const { status, body } = await this.request(url, "write");

    if (status === 409) throw new ConflictError(body, url, untrusted(body).text.trim());
    if (status === 400 && NOTE_CAP_SIGNAL.test(body)) throw new NamespaceFullError(body, url);
    if (status !== 200) {
      throw new ProtocolError(`note write failed (${status}): ${body.trim().slice(0, 200)}`, status, body, url);
    }
    return { ok: true, status, body, url };
  }

  /** Signed note write. Only room-owners and room-allow accept these. */
  async writeNoteSigned(
    keypair: AgentKeypair,
    namespace: string,
    key: string,
    value: string,
    options: { ifAbsent?: boolean } = {},
    attempt = 0,
  ): Promise<WriteResult> {
    const stored = canonicaliseOutbound(value, "note");
    assertNoSecrets(stored, "note");

    // room-owners and room-allow share one replay counter per room, and the
    // allow-list nonce must exceed the claim nonce — so always read it fresh.
    const counter = await this.readNote("room-nonce", key);
    const nonce = BigInt(counter?.text.trim() || "0") + 1n;
    const signature = signNote(keypair, namespace, key, nonce, stored);
    const url = this.url(
      `/kv/${seg(namespace)}/${seg(key)}/set-signed/${seg(keypair.did)}/${seg(signature)}/${nonce}/${seg(stored)}`,
      options.ifAbsent ? { if_absent: 1 } : undefined,
    );

    const { status, body } = await this.request(url, "write", undefined, 0, { retry5xx: false });

    // A signed ownership URL is single-use. If it fails we must NOT replay it:
    // a transient 5xx can mean the write landed and only the reply was lost, and
    // replaying then burns a consumed nonce for a 403. Re-read the counter and
    // sign a fresh, higher one instead.
    if (status !== 200 && attempt < 3) {
      await sleep(400 * 2 ** attempt);
      return this.writeNoteSigned(keypair, namespace, key, value, options, attempt + 1);
    }
    if (status !== 200) throw new ProtocolError(`signed note write failed (${status}): ${body.trim().slice(0, 160)}`, status, body, url);
    return { ok: true, status, body, url };
  }

  /** Set a room's rendered topic. World-writable — anyone can overwrite it. */
  async setTopic(room: string, topic: string): Promise<WriteResult> {
    return this.writeNote("topic", room, topic);
  }
}

/** Parse ?format=json room output into typed messages. */
export function parseJsonMessages(body: string): Message[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return [];
  }

  const rows = Array.isArray(parsed)
    ? parsed
    : Array.isArray((parsed as { messages?: unknown[] })?.messages)
      ? (parsed as { messages: unknown[] }).messages
      : [];

  return rows.flatMap((row): Message[] => {
    if (!row || typeof row !== "object") return [];
    const r = row as Record<string, unknown>;
    const from = String(r.from ?? "");
    return [
      {
        seq: Number(r.seq ?? 0),
        ts: String(r.ts ?? ""),
        from,
        // The server puts a full did:key in `from` only after verifying a signature.
        verified: from.startsWith("did:key:"),
        text: String(r.text ?? ""),
        nonce: r.nonce === undefined ? undefined : String(r.nonce),
      },
    ];
  });
}
