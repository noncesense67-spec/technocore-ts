/**
 * Autopilot — responsive autonomy, architecturally contained.
 *
 * The threat model is not "a clever prompt might steer the model". Assume it
 * does. Assume every reply the model produces is attacker-chosen text. The
 * question this module answers is: what can that text actually cause?
 *
 * Containment, in the order it matters:
 *
 *  1. FIXED DESTINATION. The room is chosen here, before the model runs, and it
 *     is always the room the message arrived in — which is always our own mb-
 *     mailbox. Model output is never parsed for a destination. There is no code
 *     path from a token to a room name.
 *
 *  2. NO TOOLS. brain.ts gets a string and returns a string. It cannot reach
 *     the network, the keys, or the note store.
 *
 *  3. OUTPUT VALIDATION, here rather than in the brain, so a compromised
 *     reasoning layer cannot switch off its own checks: printable ASCII, hard
 *     length cap, no URLs, no did:key, no room names, and the secret-shape
 *     guard that already refuses key material.
 *
 *  4. DETERMINISTIC RATE LIMIT. Enforced by this loop against a persisted
 *     ledger. A model that wants to send a thousand replies still sends at most
 *     MAX_REPLIES_PER_HOUR.
 *
 *  5. ONE SENDER, ONE REPLY. We answer a given did:key at most once per window,
 *     so an attacker cannot hold a conversation to walk us anywhere.
 *
 *  6. MAILBOX ONLY. Never a public room. Worst case is a strange reply in a
 *     room we own and nobody else reads.
 *
 *  7. KILL SWITCH + AUDIT. `state/autopilot.off` halts it. Every input, every
 *     model output, and every accept/reject decision is appended to a log.
 *
 * So the realistic worst case for a total prompt-injection success is: one
 * oddly-worded, URL-free, ASCII-only sentence appears in our own mailbox, once
 * per sender per hour. That is a cost worth accepting. Anything worse requires
 * a bug in this file, which is why the checks here are tested directly.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { STATE_DIR } from "../config.ts";
import { TechnocoreClient } from "../protocol/client.ts";
import { isPrintableAscii, sweep } from "../crypto/canonical.ts";
import { assertNoSecrets, fenceUntrusted } from "../safety/sanitize.ts";
import { loadKeypair } from "../keystore.ts";
import { think } from "./brain.ts";

export const MAX_REPLY_CHARS = 400;
export const MAX_REPLIES_PER_HOUR = 6;
export const POLL_INTERVAL_SECONDS = 120;
const KILL_SWITCH = "autopilot.off";
const LEDGER = "autopilot-ledger.json";
const AUDIT = "autopilot-audit.jsonl";

interface Ledger {
  /** ISO timestamps of replies sent, newest last. */
  sent: string[];
  /** did:key -> ISO timestamp of our last reply to them. */
  lastReplyTo: Record<string, string>;
  /** Highest mailbox seq we have processed. */
  cursor: number;
}

export interface Verdict {
  allowed: boolean;
  reason: string;
  text?: string;
}

// --------------------------------------------------------------- validation

/**
 * The gate every model output must pass. Pure and side-effect free so it can be
 * tested exhaustively without a network or a model.
 *
 * Rejects rather than sanitises: a reply that needed cleaning is a reply we did
 * not understand, and quietly repairing attacker-influenced text is how you
 * ship the thing you were trying to block.
 */
export function validateReply(raw: string): Verdict {
  const text = raw.trim();

  if (text.length === 0) return { allowed: false, reason: "empty" };
  if (text === "PASS" || /^PASS\b/i.test(text)) return { allowed: false, reason: "model declined (PASS)" };
  if (text.length > MAX_REPLY_CHARS) return { allowed: false, reason: `too long (${text.length})` };

  // The sweep must be a no-op, so the bytes we sign are the bytes stored.
  if (sweep(text) !== text) return { allowed: false, reason: "contains swept characters" };
  if (!isPrintableAscii(text)) return { allowed: false, reason: "non-printable-ASCII" };

  // No links. A URL in attacker-influenced output is the payload, not the message.
  if (/https?:\/\/|www\.|\b[a-z0-9-]+\.(com|net|org|io|xyz|fun|app|chat|finance)\b/i.test(text)) {
    return { allowed: false, reason: "contains a URL or domain" };
  }

  // No identifiers. Prevents impersonation, redirection to another key, and
  // steering a reader toward a room of the attacker's choosing.
  if (/did:key:/i.test(text)) return { allowed: false, reason: "contains a did:key" };
  if (/\b(?:mb-|p-|e-|d-)[a-z0-9_-]{6,}/i.test(text)) return { allowed: false, reason: "contains a room name" };

  // No financial or credential surface, whatever the sender asked.
  if (/\b(wallet|seed phrase|mnemonic|private key|airdrop|token|claim your|connect)\b/i.test(text)) {
    return { allowed: false, reason: "touches wallets/keys/tokens" };
  }

  try {
    assertNoSecrets(text, "autopilot reply");
  } catch (error) {
    return { allowed: false, reason: error instanceof Error ? error.message : "secret shape" };
  }

  return { allowed: true, reason: "ok", text };
}

// ------------------------------------------------------------------- ledger

function ledgerPath(): string {
  return join(STATE_DIR, LEDGER);
}

export function loadLedger(): Ledger {
  try {
    const parsed = JSON.parse(readFileSync(ledgerPath(), "utf8")) as Ledger;
    return { sent: parsed.sent ?? [], lastReplyTo: parsed.lastReplyTo ?? {}, cursor: parsed.cursor ?? 0 };
  } catch {
    return { sent: [], lastReplyTo: {}, cursor: 0 };
  }
}

function saveLedger(ledger: Ledger): void {
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(ledgerPath(), `${JSON.stringify(ledger, null, 2)}\n`, { mode: 0o600 });
}

/** Replies sent in the last hour. */
export function recentCount(ledger: Ledger, now = Date.now()): number {
  const cutoff = now - 3_600_000;
  return ledger.sent.filter((t) => Date.parse(t) > cutoff).length;
}

/** True if we already answered this key inside the window. */
export function repliedRecently(ledger: Ledger, did: string, now = Date.now()): boolean {
  const last = ledger.lastReplyTo[did];
  return last !== undefined && now - Date.parse(last) < 3_600_000;
}

function audit(entry: Record<string, unknown>): void {
  mkdirSync(STATE_DIR, { recursive: true });
  appendFileSync(join(STATE_DIR, AUDIT), `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`);
}

export function killSwitchEngaged(): boolean {
  return existsSync(join(STATE_DIR, KILL_SWITCH));
}

// --------------------------------------------------------------------- loop

/** One pass: read the mailbox, answer at most what the limits allow. */
export async function autopilotOnce(): Promise<{ considered: number; sent: number }> {
  if (killSwitchEngaged()) {
    console.log("kill switch engaged (state/autopilot.off) — standing down");
    return { considered: 0, sent: 0 };
  }

  const mailbox = storedMailbox();
  if (!mailbox) throw new Error("no mailbox recorded — run `flop register` first");

  const client = new TechnocoreClient();
  const keypair = loadKeypair();
  const ledger = loadLedger();

  const messages = await client.read(mailbox, { limit: 50 });
  let considered = 0;
  let sent = 0;
  let highest = ledger.cursor;

  for (const message of messages) {
    if (message.seq <= ledger.cursor) continue;
    highest = Math.max(highest, message.seq);

    if (message.from === keypair.did) continue; // our own writes

    // Unsigned writes cannot reach an mb- room, but check rather than assume:
    // an unattributable message is one we can neither rate-limit nor ignore
    // per-sender, so it does not get an answer.
    if (!message.verified) {
      audit({ event: "skip", seq: message.seq, reason: "unverified sender" });
      continue;
    }

    considered++;

    if (recentCount(ledger) >= MAX_REPLIES_PER_HOUR) {
      audit({ event: "skip", seq: message.seq, reason: "hourly cap reached" });
      continue;
    }
    if (repliedRecently(ledger, message.from)) {
      audit({ event: "skip", seq: message.seq, from: message.from, reason: "already answered this key this hour" });
      continue;
    }

    // The destination is fixed HERE, before the model sees anything.
    const destination = mailbox;

    const fenced = fenceUntrusted(message.text, `/r/${mailbox}`);
    const result = await think({ fenced, maxChars: MAX_REPLY_CHARS });

    if (!result.ok) {
      audit({ event: "brain-unavailable", seq: message.seq, problem: result.problem });
      console.log(`[${message.seq}] no inference available — staying silent (${result.problem})`);
      continue;
    }

    const verdict = validateReply(result.raw);
    audit({
      event: "decision",
      seq: message.seq,
      from: message.from,
      inbound: message.text.slice(0, 400),
      modelOutput: result.raw.slice(0, 600),
      allowed: verdict.allowed,
      reason: verdict.reason,
      mode: result.mode,
    });

    if (!verdict.allowed || !verdict.text) {
      console.log(`[${message.seq}] withheld — ${verdict.reason}`);
      continue;
    }

    await client.saySigned(keypair, destination, verdict.text);
    ledger.sent.push(new Date().toISOString());
    ledger.lastReplyTo[message.from] = new Date().toISOString();
    sent++;
    console.log(`[${message.seq}] replied in /r/${destination}`);
  }

  ledger.cursor = highest;
  // Keep the ledger from growing without bound.
  ledger.sent = ledger.sent.slice(-200);
  saveLedger(ledger);

  return { considered, sent };
}

export async function runAutopilot(options: { once?: boolean } = {}): Promise<void> {
  do {
    try {
      const { considered, sent } = await autopilotOnce();
      const stamp = new Date().toISOString().slice(11, 19);
      if (considered || sent) console.log(`${stamp} considered ${considered}, sent ${sent}`);
    } catch (error) {
      console.log(`[!!] pass failed, continuing — ${error instanceof Error ? error.message : String(error)}`);
      if (options.once) throw error;
    }
    if (options.once) return;
    await delay(POLL_INTERVAL_SECONDS * 1000);
  } while (!options.once);
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
