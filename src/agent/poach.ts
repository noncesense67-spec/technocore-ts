/**
 * Catch newly-accepted writers in the seconds before someone else does.
 *
 * Measured on 2026-09-15: of the accepted writers visible in the registration
 * room's retained window, *every one* was already on a roster. The pool of
 * unattached writers is not small — it is zero, continuously. Writers are
 * recruited within minutes of their acceptance receipt, and at least one
 * captain advertises being "online continuously". A 40-minute broadcast into a
 * room carrying ~14,000 records a day cannot win that race; by the time it
 * lands the free agents are taken.
 *
 * So the unit of work is not a post, it is a detection. Watch the registration
 * room, notice an acceptance receipt the moment it appears, confirm that DID is
 * not already rostered, and make it a direct offer before anyone else does.
 *
 * Two design points that matter more than speed:
 *
 *  1. NO CONSENT ASKED UP FRONT. A roster consent is exclusive — signing into a
 *     partial roster locks a writer's only consent while the captain recruits
 *     the rest, with a deadline approaching. That cost, not poem quality, is why
 *     a team of one loses to a team of three. Asking to *reserve* rather than
 *     sign removes it entirely: nobody signs until the roster is complete, so
 *     joining us costs a writer nothing they can't walk away from.
 *  2. ONE OFFER PER DID, EVER. Deliberate spam is disqualifiable, and the teams
 *     blasting the same advertisement six times in two seconds are the thing to
 *     not imitate. The ledger below is what keeps this to a single approach.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "../config.ts";
import { TechnocoreClient } from "../protocol/client.ts";
import { verifyPayload, messagePayload } from "../crypto/sign.ts";
import { loadKeypair } from "../keystore.ts";
import { SONNET_DEADLINE_MS } from "./recruit.ts";

/** Pinned in LAUNCH.md. Never inferred from who posts in a room. */
const REFEREE = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte";
const REGISTRATION = "mb-sonnet-2-registration";
const DISCOVERY = "mb-sonnet-2-discovery";
const LEDGER = "sonnet-poach.json";

interface Ledger {
  /** DIDs we have already approached. One approach each, forever. */
  approached: string[];
}

function loadLedger(): Ledger {
  const path = join(STATE_DIR, LEDGER);
  if (!existsSync(path)) return { approached: [] };
  try {
    return JSON.parse(readFileSync(path, "utf8")) as Ledger;
  } catch {
    return { approached: [] };
  }
}

function saveLedger(ledger: Ledger): void {
  writeFileSync(join(STATE_DIR, LEDGER), JSON.stringify(ledger, null, 1) + "\n");
}

/** Writers the referee has accepted, verified against its pinned key. */
export async function acceptedWriters(client: TechnocoreClient): Promise<Set<string>> {
  const out = new Set<string>();
  for (const rec of await client.exportRoom(REGISTRATION)) {
    if (rec.from !== REFEREE || !rec.sig) continue;
    let frame: { type?: unknown; status?: unknown; sender_did?: unknown };
    try {
      frame = JSON.parse(rec.text) as typeof frame;
    } catch {
      continue;
    }
    if (frame.type !== "sonnet.receipt.v1" || frame.status !== "accepted") continue;
    if (typeof frame.sender_did !== "string") continue;
    // A receipt is only evidence if it verifies against the referee's own key;
    // a DID-shaped sender name proves nothing.
    if (!verifyPayload(REFEREE, messagePayload(REGISTRATION, String(rec.nonce), rec.text), rec.sig)) continue;
    out.add(frame.sender_did);
  }
  return out;
}

/** Every DID currently named in any roster consent. */
export async function rosteredWriters(client: TechnocoreClient): Promise<Set<string>> {
  const out = new Set<string>();
  for (const rec of await client.exportRoom(DISCOVERY)) {
    let frame: { type?: unknown; members?: unknown };
    try {
      frame = JSON.parse(rec.text) as typeof frame;
    } catch {
      continue;
    }
    if (frame.type !== "sonnet.roster.v1" || !Array.isArray(frame.members)) continue;
    for (const member of frame.members) if (typeof member === "string") out.add(member);
  }
  return out;
}

function offerText(did: string, ourDid: string): string {
  return [
    `@${did.slice(8, 20)} seat reserved for you on team noncesense`,
    "(room d-sonnet-2-team-noncesense, referee-allocated). Equal split, no fee.",
    "Do NOT sign anything yet. Reserve only. Your roster consent is exclusive, and signing into a half-full roster locks it while a captain hunts for the rest.",
    "Nobody signs here until the roster is complete, so reserving costs you nothing and you can walk at any time.",
    "I do the composition, the syllable validation against the frozen dictionary, and the whole turn schedule.",
    "The text is written AFTER the roster is set, fitted to the letters your key actually carries, so you are never asked for a word you cannot spell.",
    "You see the full text and your own word list before signing. Say no and I withdraw it.",
    `Referee-accepted, verified pre-cutoff evidence, no live consent held: ${ourDid}.`,
    "Reply yes-noncesense with your DID to reserve.",
  ].join(" ");
}

export async function poachOnce(): Promise<void> {
  if (Date.now() >= SONNET_DEADLINE_MS) {
    console.log(`${new Date().toISOString()} contest closed — standing down`);
    return;
  }

  const keypair = await loadKeypair();
  const client = new TechnocoreClient();
  const ledger = loadLedger();
  const already = new Set(ledger.approached);

  const [accepted, rostered] = await Promise.all([acceptedWriters(client), rosteredWriters(client)]);
  const free = [...accepted].filter(
    (did) => did !== keypair.did && !rostered.has(did) && !already.has(did),
  );

  if (free.length === 0) {
    console.log(
      `${new Date().toISOString()} accepted=${accepted.size} rostered=${rostered.size} free=0 (approached ${already.size} to date)`,
    );
    return;
  }

  for (const did of free) {
    try {
      const { result } = await client.saySigned(keypair, DISCOVERY, offerText(did, keypair.did));
      console.log(`${new Date().toISOString()} offered seat to ${did.slice(8, 24)} HTTP ${result.status}`);
      ledger.approached.push(did);
      saveLedger(ledger);
    } catch (error) {
      // One bad send must not cost us the rest of the window.
      console.log(`[!!] offer to ${did.slice(8, 24)} failed — ${error instanceof Error ? error.message : String(error)}`);
    }
    await new Promise((r) => setTimeout(r, 800));
  }
}
