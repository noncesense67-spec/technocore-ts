/**
 * Keepalive — defence against the 7-day reclaim.
 *
 * `retention_seconds` is 604800 and it applies to notes, not just rooms. A note
 * with no write for 7 days is deleted. That means a DID registration is not a
 * durable record at all: it is a lease, and the published instructions never
 * say so. An agent that registers once and walks away disappears from the
 * registry roughly a week later, most likely before any Q4 snapshot.
 *
 * Refreshing every 24 hours leaves six days of slack, so several consecutive
 * missed runs are survivable.
 *
 * Rewriting our own note also re-establishes it if it was reclaimed while the
 * namespace had free slots — which makes this the recovery path as well as the
 * prevention.
 */

import { setTimeout as delay } from "node:timers/promises";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
  CONTRIB_NAMESPACE,
  DID_NAMESPACE,
  KEEPALIVE_INTERVAL_HOURS,
  STATE_DIR,
} from "../config.ts";
import { NamespaceFullError, TechnocoreClient } from "../protocol/client.ts";
import { fingerprint } from "../crypto/fingerprint.ts";
import { loadOrCreateX25519 } from "../crypto/x25519.ts";
import { loadKeypair } from "../keystore.ts";
import { didNote } from "./persona.ts";

interface KeepaliveOutcome {
  note: string;
  ok: boolean;
  detail: string;
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

/** One refresh pass over every note this agent owns. */
export async function keepaliveOnce(): Promise<KeepaliveOutcome[]> {
  const client = new TechnocoreClient();
  const keypair = loadKeypair();
  const x = loadOrCreateX25519();
  const fp = fingerprint(keypair.did);
  const mailbox = storedMailbox() ?? "unset";
  const outcomes: KeepaliveOutcome[] = [];

  // The DID note. Rewriting the same value is enough to reset the idle timer;
  // if the note was reclaimed, this re-establishes it when a slot is free.
  const value = didNote({ did: keypair.did, x25519PublicKey: x.publicKeyB64Url, mailbox });
  try {
    await client.writeNote(DID_NAMESPACE, fp, value);
    outcomes.push({ note: `/kv/${DID_NAMESPACE}/${fp}`, ok: true, detail: "refreshed" });
  } catch (error) {
    const detail =
      error instanceof NamespaceFullError
        ? "namespace at cap and we hold no slot yet — run `flop claim`"
        : String(error);
    outcomes.push({ note: `/kv/${DID_NAMESPACE}/${fp}`, ok: false, detail });
  }

  // The contribution note, which we do hold.
  try {
    const existing = await client.readNote(CONTRIB_NAMESPACE, fp);
    if (existing) {
      await client.writeNote(CONTRIB_NAMESPACE, fp, existing.text.trim());
      outcomes.push({ note: `/kv/${CONTRIB_NAMESPACE}/${fp}`, ok: true, detail: "refreshed" });
    }
  } catch (error) {
    outcomes.push({ note: `/kv/${CONTRIB_NAMESPACE}/${fp}`, ok: false, detail: String(error) });
  }

  return outcomes;
}

export async function runKeepalive(options: { once?: boolean } = {}): Promise<void> {
  const intervalMs = KEEPALIVE_INTERVAL_HOURS * 3_600_000;

  do {
    const stamp = new Date().toISOString();
    const outcomes = await keepaliveOnce();
    for (const o of outcomes) {
      console.log(`${stamp} ${o.ok ? "[ok]" : "[!!]"} ${o.note} — ${o.detail}`);
    }
    if (options.once) return;
    console.log(`  next refresh in ${KEEPALIVE_INTERVAL_HOURS}h\n`);
    await delay(intervalMs);
  } while (!options.once);
}
