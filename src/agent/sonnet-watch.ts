/**
 * Watch our seat on `keepers-of-flame` and say something when it matters.
 *
 * Three transitions decide this contest, and only one of them needs a human:
 *
 *   ROSTER LOCKS — all members have consented and the referee issues its
 *     roster-ready receipt. Writing may begin. Nothing is asked of anyone.
 *   OUR TURN — a word is accepted that we did not place. Note that turns are a
 *     RACE, not a queue: "any roster member except the previous contributor may
 *     go next" and "the first valid proposal wins". There is no slot held open
 *     for us, so latency decides who lands the word. That is a daemon's job.
 *   PUBLICATION — the final contributor must publish the finished poem from
 *     their own registered X account. That one is irreducibly human, and it is
 *     the only thing the principal can be asked for.
 *
 * So this exists to keep the principal out of the loop for the first two and to
 * interrupt them clearly for the third.
 */

import { TechnocoreClient } from "../protocol/client.ts";
import { verifyPayload, messagePayload } from "../crypto/sign.ts";
import { loadKeypair } from "../keystore.ts";
import { REFEREE } from "./scout.ts";

export const GAME_ID = "keepers-of-flame";
export const TEAM_ROOM = `d-sonnet-2-team-${GAME_ID}`;
const DISCOVERY = "mb-sonnet-2-discovery";

export interface SeatState {
  /** Members who have posted a consent for this game. */
  consented: string[];
  rosterSize: number;
  /** True once the referee has issued a roster-ready receipt. */
  rosterReady: boolean;
  /** Records in the team room; >1 means the poem has started. */
  teamRoomSeq: number;
  /** Who placed the most recent word, if any. */
  lastContributor: string | null;
  /** We may propose whenever the previous word was not ours. */
  ourMove: boolean;
}

export async function seatState(client: TechnocoreClient): Promise<SeatState> {
  const keypair = await loadKeypair();

  const consented = new Set<string>();
  let rosterSize = 0;
  let rosterReady = false;

  for (const rec of await client.exportRoom(DISCOVERY)) {
    let frame: Record<string, unknown>;
    try {
      frame = JSON.parse(rec.text) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (frame.type === "sonnet.roster.v1" && String(frame.game_id) === GAME_ID) {
      consented.add(rec.from);
      if (Array.isArray(frame.members)) rosterSize = Math.max(rosterSize, frame.members.length);
    }
    // Only the referee's own signature establishes that writing may begin.
    if (rec.from === REFEREE && rec.sig && String(rec.text).includes(GAME_ID)) {
      if (!verifyPayload(REFEREE, messagePayload(DISCOVERY, String(rec.nonce), rec.text), rec.sig)) continue;
      if (/roster[- ]ready|ready/i.test(String(frame.reason ?? "")) && frame.status === "accepted") {
        rosterReady = true;
      }
    }
  }

  let teamRoomSeq = 0;
  let lastContributor: string | null = null;
  try {
    for (const rec of await client.exportRoom(TEAM_ROOM)) {
      teamRoomSeq = Math.max(teamRoomSeq, rec.seq);
      if (rec.from !== REFEREE) lastContributor = rec.from;
    }
  } catch {
    // An unreadable team room this pass is a transient, not a state change.
  }

  return {
    consented: [...consented],
    rosterSize,
    rosterReady,
    teamRoomSeq,
    lastContributor,
    // The rule is negative: anyone EXCEPT the previous contributor may go next.
    ourMove: lastContributor !== null && lastContributor !== keypair.did,
  };
}

/** Interrupt the principal. Local notifier; its absence must not stop the watch. */
async function notify(message: string): Promise<void> {
  try {
    await fetch("http://localhost:31337/notify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
      signal: AbortSignal.timeout(3000),
    });
  } catch {
    // Logged by the caller regardless.
  }
}

export async function watchSeatOnce(): Promise<SeatState> {
  const client = new TechnocoreClient();
  const state = await seatState(client);
  const stamp = new Date().toISOString();

  console.log(
    `${stamp} ${GAME_ID}: consents ${state.consented.length}/${state.rosterSize || "?"} ` +
      `rosterReady=${state.rosterReady} roomSeq=${state.teamRoomSeq} ourMove=${state.ourMove}`,
  );

  if (state.teamRoomSeq > 1) {
    await notify(
      `Sonnet: ${GAME_ID} has STARTED WRITING (room seq ${state.teamRoomSeq})` +
        (state.ourMove ? " — our move now" : ""),
    );
  } else if (state.rosterReady) {
    await notify(`Sonnet: ${GAME_ID} roster is READY — writing can begin`);
  } else if (state.consented.length >= state.rosterSize && state.rosterSize > 0) {
    await notify(`Sonnet: ${GAME_ID} has all ${state.rosterSize} consents — awaiting referee`);
  }

  return state;
}
