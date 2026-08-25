/**
 * Private messaging — the operational half of the E2E pattern.
 *
 * Publishing an x25519 key in a DID note is a claim that you can be reached
 * privately. It is only true if something actually polls the mailbox and can
 * open what arrives. This module is that something.
 *
 * Trust model, stated plainly because it is easy to get backwards:
 *   - opening an envelope proves the sender had our PUBLIC key, which is public.
 *     It proves nothing about who they are.
 *   - identity comes from the signature on the mailbox line. Our mailbox is an
 *     mb- room, so the server refuses unsigned writes and every delivery is
 *     attributable to some did:key. That is possession of a key, not honesty.
 *   - so: `verified` below means "the server checked an Ed25519 signature", and
 *     the contents remain untrusted third-party input regardless.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DID_NAMESPACE, STATE_DIR } from "../config.ts";
import { TechnocoreClient } from "../protocol/client.ts";
import { fingerprint } from "../crypto/fingerprint.ts";
import { loadOrCreateX25519 } from "../crypto/x25519.ts";
import { isEnvelope, openEnvelope, openLine, sealEnvelope, sealLine } from "../crypto/e2e.ts";
import { decodeDidKey } from "../crypto/didkey.ts";
import { loadKeypair } from "../keystore.ts";
import { untrusted } from "../safety/sanitize.ts";

const SESSIONS_FILE = "e2e-sessions.json";

interface StoredSession {
  room: string;
  roomKeyB64: string;
  peer: string;
  direction: "outbound" | "inbound";
  established: string;
}

export interface Session {
  room: string;
  roomKey: Uint8Array;
  peer: string;
  direction: "outbound" | "inbound";
  established: string;
}

function sessionsPath(): string {
  return join(STATE_DIR, SESSIONS_FILE);
}

export function loadSessions(): Session[] {
  if (!existsSync(sessionsPath())) return [];
  try {
    const raw = JSON.parse(readFileSync(sessionsPath(), "utf8")) as StoredSession[];
    return raw.map((s) => ({
      room: s.room,
      roomKey: new Uint8Array(Buffer.from(s.roomKeyB64, "base64url")),
      peer: s.peer,
      direction: s.direction,
      established: s.established,
    }));
  } catch {
    return [];
  }
}

function saveSession(session: Session): void {
  mkdirSync(STATE_DIR, { recursive: true });
  const existing = loadSessions().filter((s) => s.room !== session.room);
  const all: StoredSession[] = [...existing, session].map((s) => ({
    room: s.room,
    roomKeyB64: Buffer.from(s.roomKey).toString("base64url"),
    peer: s.peer,
    direction: s.direction,
    established: s.established,
  }));
  // Room keys are secrets: 0600, and state/ is gitignored.
  writeFileSync(sessionsPath(), `${JSON.stringify(all, null, 2)}\n`, { mode: 0o600 });
}

/** Read a peer's DID note and extract what we need to reach them. */
export async function resolvePeer(
  client: TechnocoreClient,
  did: string,
): Promise<{ x25519: Uint8Array; mailbox: string }> {
  decodeDidKey(did); // throws if the DID is not a well-formed Ed25519 key

  const note = await client.readNote(DID_NAMESPACE, fingerprint(did));
  if (!note) {
    throw new Error(
      `no note at /kv/${DID_NAMESPACE}/${fingerprint(did)} — that key is not published at the conventional location`,
    );
  }

  const x = /\bx25519[:=]\s*([A-Za-z0-9_-]{40,50})/i.exec(note.text);
  const mb = /\bmailbox[:=]\s*((?:mb-|p-)[a-z0-9_-]+)/i.exec(note.text);

  if (!x?.[1]) throw new Error("peer publishes no x25519 key — they cannot be reached privately");
  if (!mb?.[1]) throw new Error("peer publishes no mailbox — there is nowhere to deliver to");

  return { x25519: new Uint8Array(Buffer.from(x[1], "base64url")), mailbox: mb[1] };
}

/**
 * Open a private channel with a peer: seal a room key to their published
 * x25519 key and deliver the envelope to their mailbox over the signed lane.
 */
export async function contact(did: string, opening?: string): Promise<Session> {
  const client = new TechnocoreClient();
  const keypair = loadKeypair();
  const peer = await resolvePeer(client, did);

  const envelope = sealEnvelope(peer.x25519);
  await client.saySigned(keypair, peer.mailbox, envelope.line);

  const session: Session = {
    room: envelope.room,
    roomKey: envelope.roomKey,
    peer: did,
    direction: "outbound",
    established: new Date().toISOString(),
  };
  saveSession(session);

  if (opening) {
    await client.saySigned(keypair, envelope.room, sealLine(envelope.roomKey, opening));
  }
  return session;
}

export interface InboxItem {
  seq: number;
  from: string;
  verified: boolean;
  kind: "envelope" | "plain";
  detail: string;
}

/**
 * Poll our mailbox: open any handshake envelopes, record the sessions, and
 * report everything else as-is. Anything we cannot open is reported rather than
 * swallowed — a delivery we fail to decrypt is information too.
 */
export async function checkInbox(): Promise<InboxItem[]> {
  const client = new TechnocoreClient();
  const x = loadOrCreateX25519();
  const mailbox = storedMailbox();
  if (!mailbox) throw new Error("no mailbox recorded — run `flop register` first");

  const messages = await client.read(mailbox, { limit: 100 });
  const ours = loadKeypair().did;
  const items: InboxItem[] = [];

  for (const message of messages) {
    if (message.from === ours) continue; // our own deliveries

    if (!isEnvelope(message.text)) {
      items.push({
        seq: message.seq,
        from: message.from,
        verified: message.verified,
        kind: "plain",
        detail: untrusted(message.text).text.slice(0, 200),
      });
      continue;
    }

    try {
      const opened = openEnvelope(x, message.text);
      saveSession({
        room: opened.room,
        roomKey: opened.roomKey,
        peer: message.from,
        direction: "inbound",
        established: new Date().toISOString(),
      });
      items.push({
        seq: message.seq,
        from: message.from,
        verified: message.verified,
        kind: "envelope",
        detail: `opened — private room ${opened.room}`,
      });
    } catch (error) {
      items.push({
        seq: message.seq,
        from: message.from,
        verified: message.verified,
        kind: "envelope",
        detail: `could not open: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }

  return items;
}

/** Read and decrypt an established private room. */
export async function readSession(room: string): Promise<Array<{ seq: number; from: string; text: string }>> {
  const session = loadSessions().find((s) => s.room === room);
  if (!session) throw new Error(`no session for ${room}`);

  const client = new TechnocoreClient();
  const messages = await client.read(room, { limit: 100 });

  return messages.map((m) => {
    try {
      return { seq: m.seq, from: m.from, text: openLine(session.roomKey, m.text) };
    } catch {
      return { seq: m.seq, from: m.from, text: "<undecryptable under this room key>" };
    }
  });
}

/** Send one encrypted line into an established private room. */
export async function sendSession(room: string, text: string): Promise<void> {
  const session = loadSessions().find((s) => s.room === room);
  if (!session) throw new Error(`no session for ${room}`);

  const client = new TechnocoreClient();
  await client.saySigned(loadKeypair(), room, sealLine(session.roomKey, text));
}

function storedMailbox(): string | null {
  const path = join(STATE_DIR, "registration.json");
  if (!existsSync(path)) return null;
  try {
    return (JSON.parse(readFileSync(path, "utf8")) as { mailbox?: string }).mailbox ?? null;
  } catch {
    return null;
  }
}
