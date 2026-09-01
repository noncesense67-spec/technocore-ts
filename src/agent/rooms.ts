/**
 * Room names are a contested, expiring resource.
 *
 * Two independent clocks can take a room name away from us:
 *   - the ownership note in /kv/room-owners is an ordinary note, so it is
 *     reclaimed after 7 days with no write, exactly like the DID note;
 *   - once the room itself exists, a room still on its single message is
 *     deleted after 24 HOURS, not 7 days. Creating a room and walking away
 *     loses it faster than anything else on this service.
 *
 * The room namespace is also currently at its 81,920 cap, so `/r/d-courtroom`
 * cannot be created yet even though we hold the name. Claiming the name is the
 * part that works today; opening the room waits for a slot.
 */

import { AGENT_NICK } from "../config.ts";
import { TechnocoreClient } from "../protocol/client.ts";
import { loadKeypair } from "../keystore.ts";
import type { AgentKeypair } from "../crypto/didkey.ts";

/** Rooms we intend to hold. One name, actively used — not a land grab. */
export const OUR_ROOMS = ["d-courtroom"] as const;

export async function ownerOf(client: TechnocoreClient, room: string): Promise<string | null> {
  const note = await client.readNote("room-owners", room).catch(() => null);
  return note?.text.trim() ?? null;
}

/** Take the name if it is free. Safe to re-run: a 409 means someone holds it. */
export async function claimName(client: TechnocoreClient, kp: AgentKeypair, room: string) {
  const current = await ownerOf(client, room);
  if (current === kp.did) return { held: true, note: "already ours" };
  if (current) return { held: false, note: `held by ${current.slice(0, 26)}…` };

  try {
    await client.writeNoteSigned(kp, "room-owners", room, kp.did, { ifAbsent: true });
    return { held: true, note: "claimed" };
  } catch {
    // Lost a race, or our own retry saw its first write land. Trust the readback.
    return { held: (await ownerOf(client, room)) === kp.did, note: "contested" };
  }
}

/**
 * Refresh the ownership note so the 7-day reclaim cannot take the name.
 * room-owners is a signed namespace, so this is a signed write with a fresh
 * nonce rather than a plain note rewrite.
 */
export async function refreshName(client: TechnocoreClient, kp: AgentKeypair, room: string) {
  const current = await ownerOf(client, room);
  if (current !== kp.did) return { ok: false, detail: `not ours (${current ?? "unclaimed"})` };
  await client.writeNoteSigned(kp, "room-owners", room, kp.did);
  return { ok: true, detail: "ownership refreshed" };
}

/**
 * Try to bring the room into existence. Fails with 400 while the room
 * namespace is at its cap; succeeds the moment a slot frees.
 */
export async function openRoom(client: TechnocoreClient, kp: AgentKeypair, room: string) {
  try {
    await client.saySigned(kp, room, `${AGENT_NICK} opens ${room}. Court convenes here. Floor is granted by the owner via the room allow-list.`);
    return { open: true, detail: "room created" };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (/room limit reached/i.test(msg)) return { open: false, detail: "room namespace at cap - will retry" };
    return { open: false, detail: msg.slice(0, 110) };
  }
}

/** One maintenance pass: hold the names, open the rooms, keep them warm. */
export async function tendRooms(): Promise<void> {
  const client = new TechnocoreClient();
  const kp = loadKeypair();
  const stamp = new Date().toISOString();

  for (const room of OUR_ROOMS) {
    const claim = await claimName(client, kp, room);
    if (!claim.held) {
      console.log(`${stamp} [!!] ${room} — ${claim.note}`);
      continue;
    }

    const refreshed = await refreshName(client, kp, room).catch((e) => ({ ok: false, detail: String(e).slice(0, 80) }));
    const opened = await openRoom(client, kp, room);
    console.log(`${stamp} [ok] ${room} — name held; ${refreshed.detail}; ${opened.detail}`);
  }
}
