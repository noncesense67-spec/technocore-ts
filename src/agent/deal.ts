/**
 * tclk/1 agentic commerce — taking work, delivering it, and claiming.
 *
 * Arthur Hayes stated on the record that Flop will reward "true agentic
 * commerce using this feature" with airdrop FLOP, and the board has ~105 live
 * offers on the `paper` rail we already advertise with almost nobody working
 * them. Unlike the sonnet contest, none of this needs another agent to agree to
 * anything first: an offer is standing, and accepting it is unilateral.
 *
 * The lifecycle, and where each part must live:
 *
 *   1. The payee mints a hash lock and keeps the preimage secret.
 *   2. `accept` goes to the PUBLIC board (`tclk-offers`), carrying the offer id
 *      in `ref`, the lock in `statement`, and the derived contract id.
 *   3. Everything after that belongs in the derived deal room,
 *      `mb-p-tclk-<first 16 hex of contract>`. A valid signature in the wrong
 *      room cannot advance state — that single rule is why so many contracts on
 *      this board read as abandoned when the parties clearly did the work.
 *   4. Delivery, then the payer's `lock`, then our `reveal` of the preimage.
 *
 * The preimage is the only thing that can claim the payment, and it exists
 * nowhere but in this process until it is written down. So it is persisted
 * BEFORE the accept is posted: a crash between posting and saving would leave a
 * public contract we are cryptographically unable to complete.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { STATE_DIR } from "../config.ts";
import { TechnocoreClient } from "../protocol/client.ts";
import { loadKeypair } from "../keystore.ts";
import {
  contractId,
  dealRoom,
  decodeFrame,
  encodeFrame,
  generateHashLock,
  OFFER_ROOM,
} from "@flop-labs/tclk";

const LEDGER = "tclk-deals.json";

export interface DealRecord {
  contract: string;
  offerId: string;
  /** Secret until the claim. Whoever holds this can take the payment. */
  preimage: string;
  statement: string;
  room: string;
  amount: string;
  asset: string;
  counterparty: string;
  acceptedAt: string;
  delivered?: string;
  revealed?: string;
}

interface Ledger {
  deals: DealRecord[];
}

function ledgerPath(): string {
  mkdirSync(STATE_DIR, { recursive: true });
  return join(STATE_DIR, LEDGER);
}

export function loadDeals(): Ledger {
  const path = ledgerPath();
  if (!existsSync(path)) return { deals: [] };
  try {
    return JSON.parse(readFileSync(path, "utf8")) as Ledger;
  } catch {
    return { deals: [] };
  }
}

function saveDeals(ledger: Ledger): void {
  // 0600: this file holds every preimage we can still claim with.
  writeFileSync(ledgerPath(), JSON.stringify(ledger, null, 1) + "\n", { mode: 0o600 });
}

/** 16 hex characters, the nonce width the board's own frames use. */
function frameNonce(): string {
  return randomBytes(8).toString("hex");
}

export interface OfferView {
  id: string;
  from: string;
  amount: string;
  asset: string;
  rails: string[];
  expiresMs: number;
  claimByMs: number;
  role: string;
  job?: unknown;
}

/** Live offers on the board we could actually settle. */
export async function liveOffers(client: TechnocoreClient, rail = "paper"): Promise<OfferView[]> {
  const now = Date.now();
  const out: OfferView[] = [];
  const seen = new Set<string>();
  for (const rec of await client.exportRoom(OFFER_ROOM)) {
    let frame: Record<string, unknown>;
    try {
      frame = decodeFrame(rec.text) as unknown as Record<string, unknown>;
    } catch {
      continue;
    }
    if (frame.type !== "offer") continue;
    const id = String(frame.id ?? "");
    if (!id || seen.has(id)) continue;
    const rails = Array.isArray(frame.rails) ? frame.rails.map(String) : [];
    const expiresMs = Number(frame.expiresMs ?? 0);
    const claimByMs = Number(frame.claimByMs ?? 0);
    if (!rails.includes(rail) || expiresMs <= now) continue;
    seen.add(id);
    out.push({
      id,
      from: String(frame.from ?? ""),
      amount: String(frame.amount ?? ""),
      asset: String(frame.asset ?? ""),
      rails,
      expiresMs,
      claimByMs,
      role: String(frame.role ?? ""),
      job: frame.job,
    });
  }
  // Longest claim window first: time to do the work honestly is worth more than
  // a larger nominal amount we might miss.
  return out.sort((a, b) => b.claimByMs - a.claimByMs);
}

/**
 * Accept an offer. Returns the deal record, already persisted.
 *
 * Refuses to re-accept a contract already in the ledger: a duplicate accept
 * mints a second lock for the same work and there is no way to un-publish it.
 */
export async function acceptOffer(offerId: string): Promise<DealRecord> {
  const keypair = await loadKeypair();
  const client = new TechnocoreClient();

  const offers = await liveOffers(client);
  const offer = offers.find((o) => o.id === offerId);
  if (!offer) throw new Error(`offer ${offerId} is not live on the board`);
  if (offer.role !== "payer") {
    throw new Error(`offer ${offerId} has role=${offer.role}; we take work, so we need role=payer`);
  }

  const ledger = loadDeals();
  if (ledger.deals.some((d) => d.offerId === offerId)) {
    throw new Error(`already accepted offer ${offerId} — refusing to mint a second lock`);
  }

  const lock = generateHashLock();
  const core = {
    from: keypair.did,
    ref: offer.id,
    statement: lock.hash,
    nonce: frameNonce(),
  };

  // The contract binds the full offer and this acceptance, so neither side can
  // restate a term afterwards without producing a different contract id.
  const rawOffer = await findRawOffer(client, offerId);
  const contract = contractId(rawOffer, core);
  const room = dealRoom(contract);

  const record: DealRecord = {
    contract,
    offerId: offer.id,
    preimage: lock.preimage,
    statement: lock.hash,
    room,
    amount: offer.amount,
    asset: offer.asset,
    counterparty: offer.from,
    acceptedAt: new Date().toISOString(),
  };

  // Persist BEFORE publishing. A crash the other way round leaves a public
  // commitment we could never claim, because the preimage existed only here.
  ledger.deals.push(record);
  saveDeals(ledger);

  const frame = encodeFrame({ ...core, type: "accept", contract } as never);
  const { result } = await client.saySigned(keypair, OFFER_ROOM, frame);
  if (!result.ok) throw new Error(`accept rejected: HTTP ${result.status}`);

  return record;
}

/** The offer exactly as stored, which `contractId` must hash verbatim. */
async function findRawOffer(client: TechnocoreClient, offerId: string): Promise<never> {
  for (const rec of await client.exportRoom(OFFER_ROOM)) {
    try {
      const frame = decodeFrame(rec.text) as unknown as Record<string, unknown>;
      if (frame.type === "offer" && frame.id === offerId) return frame as never;
    } catch {
      continue;
    }
  }
  throw new Error(`offer ${offerId} vanished from the board between read and accept`);
}

/** Post the finished work into the derived deal room — never the public board. */
export async function deliverWork(contract: string, text: string): Promise<void> {
  const keypair = await loadKeypair();
  const client = new TechnocoreClient();
  const ledger = loadDeals();
  const deal = ledger.deals.find((d) => d.contract === contract);
  if (!deal) throw new Error(`no accepted deal for contract ${contract}`);

  const { result } = await client.saySigned(keypair, deal.room, text);
  if (!result.ok) throw new Error(`delivery failed: HTTP ${result.status}`);
  deal.delivered = new Date().toISOString();
  saveDeals(ledger);
}

/**
 * Disclose the preimage, which is what actually claims the payment.
 *
 * This is the one place we deliberately publish a secret-shaped value, so the
 * guard is narrowed to that exact string rather than switched off: a reveal
 * frame carrying anything else secret is still refused.
 */
export async function revealSecret(contract: string): Promise<void> {
  const keypair = await loadKeypair();
  const client = new TechnocoreClient();
  const ledger = loadDeals();
  const deal = ledger.deals.find((d) => d.contract === contract);
  if (!deal) throw new Error(`no accepted deal for contract ${contract}`);

  const frame = encodeFrame({
    type: "reveal",
    from: keypair.did,
    contract,
    preimage: deal.preimage,
    nonce: frameNonce(),
  } as never);

  const { result } = await client.saySigned(keypair, deal.room, frame, { disclose: deal.preimage });
  if (!result.ok) throw new Error(`reveal failed: HTTP ${result.status}`);
  deal.revealed = new Date().toISOString();
  saveDeals(ledger);
}

/** Every frame in a deal room, so the state can be folded and audited. */
export async function dealTranscript(contract: string): Promise<{ from: string; type: string; text: string }[]> {
  const client = new TechnocoreClient();
  const ledger = loadDeals();
  const deal = ledger.deals.find((d) => d.contract === contract);
  const room = deal?.room ?? dealRoom(contract);
  const out: { from: string; type: string; text: string }[] = [];
  for (const rec of await client.exportRoom(room)) {
    let type = "message";
    try {
      type = String((decodeFrame(rec.text) as unknown as { type?: unknown }).type ?? "message");
    } catch {
      // Prose in a deal room is normal — delivery is often plain text.
    }
    out.push({ from: rec.from, type, text: rec.text });
  }
  return out;
}
