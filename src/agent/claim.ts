/**
 * Claiming a slot in the `did` namespace.
 *
 * The namespace sits at its 5120-note cap, so step 2 of the published airdrop
 * instructions ("publish your DID note to /kv/did/") currently returns
 *
 *     400 note limit reached (5120 is the cap, and this would be a new one)
 *
 * for every new agent. A browser shows a blank-ish page and an agent that does
 * not read the response body concludes it registered. It did not.
 *
 * Slots reopen continuously: notes with no write for 7 days are reclaimed, and
 * a large share of the current 5120 are one-shot registrations that will never
 * be refreshed. So this is a waiting game, not a dead end — poll, and take a
 * slot the moment one frees.
 *
 * What this deliberately does NOT do: overwrite an existing note. Every key in
 * there is another agent's identity, the namespace is world-writable, and the
 * cap makes those slots contested. Taking one would be trivial and would be
 * theft of someone's registration.
 */

import { setTimeout as delay } from "node:timers/promises";
import { DID_NAMESPACE } from "../config.ts";
import { NamespaceFullError, TechnocoreClient } from "../protocol/client.ts";
import { fingerprint } from "../crypto/fingerprint.ts";
import { loadOrCreateX25519 } from "../crypto/x25519.ts";
import { loadKeypair } from "../keystore.ts";
import { didNote } from "./persona.ts";

export interface ClaimOptions {
  /** Seconds between attempts. Jittered to avoid lockstep with other claimers. */
  intervalSeconds?: number;
  /** Give up after this many attempts. Infinite when omitted. */
  maxAttempts?: number;
  /** The mailbox to advertise in the note. */
  mailbox?: string;
}

export interface ClaimResult {
  claimed: boolean;
  attempts: number;
  fingerprint: string;
  did: string;
}

/** Read the current occupancy of the did namespace. */
export async function namespaceOccupancy(client: TechnocoreClient): Promise<number> {
  return (await client.listKeys(DID_NAMESPACE)).length;
}

export async function claimDidSlot(options: ClaimOptions = {}): Promise<ClaimResult> {
  const { intervalSeconds = 45, maxAttempts } = options;
  const keypair = loadKeypair();
  const x = loadOrCreateX25519();
  const fp = fingerprint(keypair.did);
  const client = new TechnocoreClient();

  const mailbox = options.mailbox ?? (await currentMailbox());
  const value = didNote({ did: keypair.did, x25519PublicKey: x.publicKeyB64Url, mailbox });

  console.log(`Claiming /kv/${DID_NAMESPACE}/${fp}`);
  console.log(`  DID     ${keypair.did}`);
  console.log(`  polling every ~${intervalSeconds}s; the namespace frees slots as idle notes are reclaimed\n`);

  for (let attempt = 1; !maxAttempts || attempt <= maxAttempts; attempt++) {
    const stamp = () => new Date().toISOString().slice(11, 19);

    // This runs for days against a service that sheds load with 5xx. Any
    // failure that is not "you already hold it" must be survivable, or a
    // single blip ends the watch and the slot is missed silently.
    try {
      // Idempotency: if a previous run already landed it, stop.
      const existing = await client.readNote(DID_NAMESPACE, fp);
      if (existing) {
        console.log(`[${attempt}] note already present — nothing to claim.`);
        return { claimed: true, attempts: attempt, fingerprint: fp, did: keypair.did };
      }

      await client.writeNote(DID_NAMESPACE, fp, value, { ifAbsent: true });
      console.log(`\n[${attempt}] ${stamp()} CLAIMED. /kv/${DID_NAMESPACE}/${fp} is live.`);
      return { claimed: true, attempts: attempt, fingerprint: fp, did: keypair.did };
    } catch (error) {
      if (error instanceof NamespaceFullError) {
        const occupancy = await namespaceOccupancy(client).catch(() => -1);
        console.log(`[${attempt}] ${stamp()} namespace full (${occupancy}/5120) — retrying`);
      } else {
        // Transient 5xx, a network drop, a DNS hiccup. Log and keep waiting.
        const message = error instanceof Error ? error.message : String(error);
        console.log(`[${attempt}] ${stamp()} transient failure, continuing — ${message.slice(0, 120)}`);
      }
    }

    // Jitter so many claimers do not synchronise on the same instant.
    const jitter = intervalSeconds * (0.75 + Math.random() * 0.5);
    await delay(jitter * 1000);
  }

  return { claimed: false, attempts: maxAttempts ?? 0, fingerprint: fp, did: keypair.did };
}

/** Reuse the mailbox minted during registration, if there was one. */
async function currentMailbox(): Promise<string> {
  const { readFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { STATE_DIR } = await import("../config.ts");
  try {
    const record = JSON.parse(readFileSync(join(STATE_DIR, "registration.json"), "utf8")) as {
      mailbox?: string;
    };
    if (record.mailbox) return record.mailbox;
  } catch {
    // No registration record yet.
  }
  const { randomBytes } = await import("node:crypto");
  return `mb-p-${randomBytes(12).toString("hex")}`;
}
