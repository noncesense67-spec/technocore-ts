/**
 * Claiming a slot in the `did` namespace.
 *
 * Historically the namespace sat at a 5,120-note cap and step 2 of the published
 * airdrop instructions returned
 *
 *     400 note limit reached (5120 is the cap, and this would be a new one)
 *
 * for every new agent — in the response *body* of a 400, so an agent that did not
 * read the body concluded it had registered when it had not.
 *
 * Technocore 0.11.2 raised the per-namespace cap to 131,072 and the refusal no
 * longer fires in normal use. This is kept because the failure mode is real and
 * will recur if the registry grows into the new ceiling: poll, and take a slot
 * the moment one frees, rather than failing the user on their first action.
 *
 * What this deliberately does NOT do: overwrite an existing note. Every key in
 * there is another agent's identity, the namespace is world-writable, and the
 * cap makes those slots contested. Taking one would be trivial and would be
 * theft of someone's registration.
 */

import { setTimeout as delay } from "node:timers/promises";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { AGENT_REPO, DID_NAMESPACE, LIMITS, STATE_DIR } from "../config.ts";
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
  const value = didNote({
    did: keypair.did,
    x25519PublicKey: x.publicKeyB64Url,
    mailbox,
    repo: AGENT_REPO,
  });

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
        markClaimed(fp);
        console.log(`[${attempt}] note already present — nothing to claim.`);
        return { claimed: true, attempts: attempt, fingerprint: fp, did: keypair.did };
      }

      await client.writeNote(DID_NAMESPACE, fp, value, { ifAbsent: true });
      markClaimed(fp);
      console.log(`\n[${attempt}] ${stamp()} CLAIMED. /kv/${DID_NAMESPACE}/${fp} is live.`);
      return { claimed: true, attempts: attempt, fingerprint: fp, did: keypair.did };
    } catch (error) {
      if (error instanceof NamespaceFullError) {
        const occupancy = await namespaceOccupancy(client).catch(() => -1);
        console.log(`[${attempt}] ${stamp()} namespace full (${occupancy}/${LIMITS.notesPerNamespace}) — retrying`);
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

/**
 * Record that the slot was won. Health checks use this to tell "not registered
 * yet" (expected, the namespace is full) from "was registered and is now gone"
 * (an emergency — the note was reclaimed and the slot is back in contention).
 */
export function markClaimed(fp: string): void {
  const path = join(STATE_DIR, "did-claimed");
  if (existsSync(path)) return;
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(path, `${fp} ${new Date().toISOString()}\n`);
}

/** True if we have ever successfully held the DID note. */
export function hasEverClaimed(): boolean {
  return existsSync(join(STATE_DIR, "did-claimed"));
}
