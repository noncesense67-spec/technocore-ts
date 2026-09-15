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

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { STATE_DIR } from "../config.ts";
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

/**
 * A transition queued for delivery to the principal's phone.
 *
 * Detection and delivery are split deliberately. This daemon runs every 90s and
 * never stops, but it cannot reach a phone — PushNotification is a harness tool
 * available only inside a Claude session. So the daemon records WHAT changed and
 * a scheduled task drains this file and delivers it.
 *
 * Only genuine transitions are written. A notification the principal did not
 * need is annoying in a way that accumulates, and an alert every 90 seconds
 * would train them to ignore the one that matters.
 */
const ALERT_FILE = "seat-alert.json";

interface PendingAlert {
  phase: string;
  message: string;
  at: string;
}

function alertPath(): string {
  return join(STATE_DIR, ALERT_FILE);
}

function lastPhase(): string | null {
  const path = alertPath();
  if (!existsSync(path)) return null;
  try {
    return (JSON.parse(readFileSync(path, "utf8")) as { phase?: string }).phase ?? null;
  } catch {
    return null;
  }
}

/** Record a phase change for the scheduled task to deliver. */
function queueAlert(phase: string, message: string): boolean {
  if (lastPhase() === phase) return false;
  const alert: PendingAlert = { phase, message, at: new Date().toISOString() };
  writeFileSync(alertPath(), JSON.stringify(alert, null, 1) + "\n");
  return true;
}

/**
 * Reach the principal's phone, from a daemon, with no session in the loop.
 *
 * This is the only alert path here that survives the Claude app being closed:
 * launchd calls the Telegram API directly. The local Pulse notifier speaks
 * aloud, which is useless at 04:00, and a scheduled task would only run while
 * the app is open.
 *
 * The bot token is read at call time from the principal's env and never logged,
 * never persisted here, and never included in an error message — a failed send
 * reports the HTTP status only. Telegram forbids a bot opening a conversation,
 * so the chat id below exists only because the principal messaged the bot first.
 */
function telegramChatId(): string | null {
  try {
    const raw = readFileSync(join(STATE_DIR, "telegram.json"), "utf8");
    return (JSON.parse(raw) as { chatId?: string }).chatId ?? null;
  } catch {
    return null;
  }
}

function telegramToken(): string | null {
  for (const path of [join(process.env.HOME ?? "", ".claude/.env"), join(process.env.HOME ?? "", ".env")]) {
    try {
      const match = /^TELEGRAM_BOT_TOKEN=(.+)$/m.exec(readFileSync(path, "utf8"));
      if (match?.[1]) return match[1].trim().replace(/^["']|["']$/g, "");
    } catch {
      // Absent env file is normal; try the next.
    }
  }
  return null;
}

async function telegram(message: string): Promise<boolean> {
  const chatId = telegramChatId();
  const token = telegramToken();
  if (!chatId || !token) return false;
  try {
    const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: message, disable_notification: false }),
      signal: AbortSignal.timeout(8000),
    });
    return res.ok;
  } catch {
    // Never surface the token in a thrown error; the boolean is the whole report.
    return false;
  }
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

  // Phase is ordered: later phases supersede earlier ones. Consent progress is
  // part of the phase key so each teammate joining is its own one-time alert —
  // the principal asked to hear about teammates, and there are at most two such
  // events left on a four-member roster.
  const phase =
    state.teamRoomSeq > 1 ? (state.ourMove ? "our-move" : "writing")
    : state.rosterReady ? "roster-ready"
    : state.rosterSize > 0 && state.consented.length >= state.rosterSize ? "consents-complete"
    : state.consented.length > 1 ? `forming-${state.consented.length}`
    : "forming";

  const message =
    phase === "our-move" ? `SONNET: ${GAME_ID} is writing and it is OUR MOVE (room seq ${state.teamRoomSeq})`
    : phase === "writing" ? `SONNET: ${GAME_ID} has started writing (room seq ${state.teamRoomSeq})`
    : phase === "roster-ready" ? `SONNET: ${GAME_ID} roster is READY — writing can begin`
    : phase === "consents-complete" ? `SONNET: ${GAME_ID} has all ${state.rosterSize} consents — awaiting referee`
    : `SONNET: teammate joined ${GAME_ID} — ${state.consented.length}/${state.rosterSize || "?"} consents signed`;

  if (phase !== "forming" && queueAlert(phase, message)) {
    const sent = await telegram(message);
    console.log(`${stamp} TRANSITION -> ${phase} (telegram ${sent ? "sent" : "FAILED"})`);
    await notify(message);
  }

  return state;
}
