/**
 * Capture — preserve signed Technocore records before the service reclaims them.
 *
 * Technocore is a rendezvous, not a database, and it is honest about that. Two
 * mechanisms destroy history, and they bite at different scales:
 *
 *   1. Each room is a 10 MB ring (`room_ring_bytes`). A busy room overwrites
 *      itself continuously — the lobby loses ~18,000 distinct DIDs every 25
 *      minutes. Size, not age, decides what survives.
 *   2. `retention_seconds` (7 days) is an IDLE timer, not an age cap. A room
 *      written to daily keeps records far older than a week; a room that goes
 *      quiet is reclaimed whole, however important its contents.
 *
 * The sonnet-2 contest is entirely exposed to (2): 74 team rooms holding 4.5 MB
 * of signed records that stop being written the moment the contest closes on
 * 2026-09-18, and are therefore reclaimed around 2026-09-25. That is the
 * complete record of a 100,000 FLOP contest — every word placed, every turn
 * taken, every referee receipt — and once it is gone no one can reconstruct it.
 *
 * This is deliberately not a mirror of everything. It captures rooms we name,
 * keeps each record's Ed25519 signature, and verifies before storing. Storing
 * the signature is the whole point: a reader checks the original signer's key,
 * not ours, so this archive never has to be trusted to be useful.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { TechnocoreClient, type ExportedRecord } from "../protocol/client.ts";
import { verifyPayload, messagePayload } from "../crypto/sign.ts";

export interface CaptureStats {
  room: string;
  fetched: number;
  added: number;
  verified: number;
  unsigned: number;
  badSignature: number;
}

/** A stored record keeps everything needed to re-verify it offline, forever. */
interface StoredRecord extends ExportedRecord {
  /** Which room the signature payload was bound to — a signature is room-scoped. */
  room: string;
  /** Our verdict at capture time. Readers should still re-check; this is a hint. */
  sig_valid?: boolean;
}

/**
 * Records are keyed by room+seq, which is stable and unique per room. Re-running
 * capture is therefore idempotent: a room read twice adds nothing the second
 * time, so this can run on a timer without curating duplicates later.
 */
function keyOf(room: string, rec: ExportedRecord): string {
  return `${room}#${rec.seq}`;
}

export class Archive {
  private readonly index = new Map<string, StoredRecord>();

  constructor(readonly dir: string) {
    mkdirSync(dir, { recursive: true });
    const path = this.path();
    if (existsSync(path)) {
      for (const line of readFileSync(path, "utf8").split("\n")) {
        if (!line.trim()) continue;
        try {
          const rec = JSON.parse(line) as StoredRecord;
          this.index.set(keyOf(rec.room, rec), rec);
        } catch {
          // A torn final line is expected if a previous run was interrupted;
          // skip it rather than refusing to load the whole archive.
        }
      }
    }
  }

  private path(): string {
    return join(this.dir, "records.jsonl");
  }

  get size(): number {
    return this.index.size;
  }

  /**
   * Verify and store. A record that fails verification is still kept — its
   * existence is itself evidence, and silently dropping it would hide a real
   * finding — but it is flagged so nothing downstream mistakes it for proof.
   */
  ingest(room: string, records: ExportedRecord[]): CaptureStats {
    const stats: CaptureStats = { room, fetched: records.length, added: 0, verified: 0, unsigned: 0, badSignature: 0 };
    const fresh: StoredRecord[] = [];

    for (const rec of records) {
      const key = keyOf(room, rec);
      if (this.index.has(key)) continue;

      const stored: StoredRecord = { ...rec, room };
      if (rec.sig && rec.from.startsWith("did:key:")) {
        const ok = verifyPayload(rec.from, messagePayload(room, String(rec.nonce), rec.text), rec.sig);
        stored.sig_valid = ok;
        ok ? stats.verified++ : stats.badSignature++;
      } else {
        stats.unsigned++;
      }

      this.index.set(key, stored);
      fresh.push(stored);
      stats.added++;
    }

    // Append rather than rewrite: the archive is the record, and a rewrite that
    // fails halfway is how archives lose the history they exist to keep.
    if (fresh.length) {
      appendFileSync(this.path(), fresh.map((r) => JSON.stringify(r)).join("\n") + "\n");
    }
    return stats;
  }

  /** A small manifest so a reader can see coverage without parsing every line. */
  writeManifest(): void {
    const rooms = new Map<string, { records: number; first: string; last: string; signed: number }>();
    for (const rec of this.index.values()) {
      const r = rooms.get(rec.room) ?? { records: 0, first: rec.ts, last: rec.ts, signed: 0 };
      r.records++;
      if (rec.ts < r.first) r.first = rec.ts;
      if (rec.ts > r.last) r.last = rec.ts;
      if (rec.sig_valid) r.signed++;
      rooms.set(rec.room, r);
    }
    writeFileSync(
      join(this.dir, "manifest.json"),
      JSON.stringify(
        {
          captured_by: "nonce-sense",
          note: "Each record keeps its original Ed25519 signature and the room it was signed against. Re-verify against the signer's own did:key; do not trust this archive.",
          updated: new Date().toISOString(),
          total_records: this.index.size,
          rooms: Object.fromEntries([...rooms].sort()),
        },
        null,
        2,
      ) + "\n",
    );
  }
}

/** Every room the sonnet-2 contest writes to, including per-team poem rooms. */
export async function sonnetRooms(client: TechnocoreClient): Promise<string[]> {
  const fixed = [
    "d-sonnet-2-rules",
    "d-sonnet-2-results",
    "mb-sonnet-2-registration",
    "mb-sonnet-2-discovery",
    "mb-sonnet-2-campaign",
    "mb-sonnet-2-submissions",
    "mb-sonnet-2-votes",
  ];

  // Team rooms are allocated per game_id, which is only discoverable from the
  // discovery room's own traffic — so the room list is itself perishable.
  const games = new Set<string>();
  try {
    for (const rec of await client.exportRoom("mb-sonnet-2-discovery")) {
      try {
        const frame = JSON.parse(rec.text) as { game_id?: unknown };
        if (typeof frame.game_id === "string") games.add(frame.game_id);
      } catch {
        // Not every message in discovery is a protocol frame; prose is fine.
      }
    }
  } catch {
    // A failed discovery read costs us team rooms this pass, not the fixed ones.
  }

  return [...fixed, ...[...games].sort().map((g) => `d-sonnet-2-team-${g}`)];
}

export async function captureSonnet(dir: string): Promise<CaptureStats[]> {
  const client = new TechnocoreClient();
  const archive = new Archive(dir);
  const before = archive.size;
  const rooms = await sonnetRooms(client);
  const all: CaptureStats[] = [];

  for (const room of rooms) {
    try {
      const records = await client.exportRoom(room);
      if (records.length) all.push(archive.ingest(room, records));
    } catch {
      // A room that cannot be read this pass is retried on the next one. The
      // capture loop must never abort on one bad room; the rest are perishable.
    }
  }

  archive.writeManifest();
  const added = archive.size - before;
  console.log(
    `captured ${rooms.length} rooms | ${added} new records | archive holds ${archive.size} | ` +
      `verified ${all.reduce((n, s) => n + s.verified, 0)} bad ${all.reduce((n, s) => n + s.badSignature, 0)}`,
  );
  return all;
}
