/**
 * Find a team worth spending our one roster consent on.
 *
 * Three "open seat" offers have now turned out to be worthless, and each failed
 * a different way, which is why this checks all three:
 *
 *   VALIANT   advertised a "pre-solved sonnet ready" into an empty room.
 *   luxion-1  pinged us directly; the referee had rejected its room request
 *             ("room request: writer or organizer") — its captain is not a
 *             registered writer.
 *   flopdsh   went further and put our DID on a roster we never consented to.
 *             The referee rejected that roster ("roster: unregistered") and two
 *             members' consents ("consent: withdraw before changing" — they
 *             already held consent elsewhere).
 *
 * The last is the dangerous shape: automated roster-stuffing (`lgflopdsh-auto-`,
 * `luxion-autosign-`) that manufactures the *appearance* of a team. Appearing on
 * a roster proves nothing. Only the referee's signed verdict does, and a roster
 * consent is exclusive and cannot be un-spent, so the cost of trusting an ad is
 * the whole contest.
 *
 * A team is worth approaching only if the referee has ACCEPTED its setup, has
 * not rejected its most recent roster, it has not yet frozen membership with a
 * first word, and it has room under the eight-member cap.
 */

import { TechnocoreClient } from "../protocol/client.ts";
import { verifyPayload, messagePayload } from "../crypto/sign.ts";

/** Pinned in LAUNCH.md. Never inferred from who posts in a room. */
export const REFEREE = "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte";
const DISCOVERY = "mb-sonnet-2-discovery";

export interface TeamVerdict {
  gameId: string;
  /** Latest referee status for anything naming this game, newest last. */
  setupAccepted: boolean;
  rosterRejected: boolean;
  lastReason: string;
  members: string[];
  rosterGeneration: number | null;
}

/**
 * Referee verdicts, keyed by game. Receipts arrive singly and batched under a
 * `receipts` array; both carry the game they judge, so both are unpacked.
 */
export async function refereeVerdicts(client: TechnocoreClient): Promise<Map<string, TeamVerdict>> {
  const out = new Map<string, TeamVerdict>();
  const ensure = (gameId: string): TeamVerdict =>
    out.get(gameId) ??
    (out.set(gameId, {
      gameId,
      setupAccepted: false,
      rosterRejected: false,
      lastReason: "",
      members: [],
      rosterGeneration: null,
    }),
    out.get(gameId)!);

  for (const rec of await client.exportRoom(DISCOVERY)) {
    let frame: Record<string, unknown>;
    try {
      frame = JSON.parse(rec.text) as Record<string, unknown>;
    } catch {
      continue;
    }

    // A roster is a claim by a participant, not evidence. Record who it names
    // so we can report it, but never treat it as admission.
    if (frame.type === "sonnet.roster.v1" && Array.isArray(frame.members)) {
      const team = ensure(String(frame.game_id));
      team.members = frame.members.filter((m): m is string => typeof m === "string");
      team.rosterGeneration =
        typeof frame.room_generation === "number" ? frame.room_generation : team.rosterGeneration;
      continue;
    }

    if (rec.from !== REFEREE || !rec.sig) continue;
    if (!verifyPayload(REFEREE, messagePayload(DISCOVERY, String(rec.nonce), rec.text), rec.sig)) continue;

    const entries = Array.isArray(frame.receipts) ? frame.receipts : [frame];
    for (const raw of entries) {
      const entry = raw as Record<string, unknown>;
      const gameId = entry.game_id ?? frame.game_id;
      if (typeof gameId !== "string") continue;
      const status = String(entry.status ?? frame.status ?? "");
      const reason = String(entry.reason ?? frame.reason ?? "");
      const team = ensure(gameId);
      if (reason) team.lastReason = reason;

      if (status === "accepted") {
        team.setupAccepted = true;
        // An acceptance supersedes an earlier roster refusal for this game.
        if (/roster/i.test(reason)) team.rosterRejected = false;
      } else if (status === "rejected") {
        if (/roster|consent/i.test(reason)) team.rosterRejected = true;
        // A refused room request means the game was never validly set up.
        if (/room request/i.test(reason)) team.setupAccepted = false;
      }
    }
  }
  return out;
}

export interface Candidate extends TeamVerdict {
  lastSeq: number;
  generation: number | null;
  seatsFree: number;
}

/** Has the team frozen membership by placing a first word? */
async function roomState(gameId: string): Promise<{ lastSeq: number; generation: number | null }> {
  try {
    const res = await fetch(
      `https://technocore.chat/r/d-sonnet-2-team-${encodeURIComponent(gameId)}?format=json&limit=1`,
    );
    if (!res.ok) return { lastSeq: -1, generation: null };
    const body = (await res.json()) as { last_seq?: number; generation?: number };
    return { lastSeq: body.last_seq ?? 0, generation: body.generation ?? null };
  } catch {
    return { lastSeq: -1, generation: null };
  }
}

/**
 * Teams actually worth an application. `maxSeq` is the tolerance for "has not
 * started writing": a provisioned room carries a setup record or two, so a
 * handful of records is still pre-first-word, while a room deep into a poem is
 * frozen and cannot admit anyone.
 */
export async function findLegitTeams(client: TechnocoreClient, maxSeq = 6): Promise<Candidate[]> {
  const verdicts = await refereeVerdicts(client);
  const out: Candidate[] = [];

  for (const team of verdicts.values()) {
    if (!team.setupAccepted || team.rosterRejected) continue;
    if (team.members.length >= 8) continue;
    const { lastSeq, generation } = await roomState(team.gameId);
    if (lastSeq < 0 || lastSeq > maxSeq) continue;
    out.push({ ...team, lastSeq, generation, seatsFree: 8 - team.members.length });
  }
  // Teams with a signed roster are closer to writing than bare allocations.
  return out.sort((a, b) => b.members.length - a.members.length);
}
