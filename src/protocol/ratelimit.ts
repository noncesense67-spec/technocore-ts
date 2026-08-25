/**
 * Client-side pacing.
 *
 * The server runs two token buckets per client IP — one for reads, one for
 * writes — refilling continuously. A burst up to a full bucket is fine and a
 * steady drip never trips. We mirror those buckets locally so we self-pace
 * instead of discovering the limit by being throttled.
 *
 * Two server signals are also honoured:
 *   - replies append "# budget: <left> of <max> reads left this minute" once we
 *     drop below a quarter bucket; we resync from it for free.
 *   - a 429 states the bucket, refill rate and wait seconds in its BODY (and in
 *     Retry-After); we back off for exactly that long.
 */

import { LIMITS } from "../config.ts";

export type Bucket = "read" | "write";

const BUDGET_FOOTER = /#\s*budget:\s*(\d+)\s+of\s+(\d+)\s+(read|write)s?\s+left/i;
const RETRY_SECONDS = /(\d+(?:\.\d+)?)\s*second/i;

class TokenBucket {
  private tokens: number;
  private lastRefill = Date.now();

  constructor(
    private readonly capacity: number,
    private readonly perMinute: number,
  ) {
    this.tokens = capacity;
  }

  private refill(): void {
    const now = Date.now();
    const elapsedMinutes = (now - this.lastRefill) / 60_000;
    if (elapsedMinutes <= 0) return;
    this.tokens = Math.min(this.capacity, this.tokens + elapsedMinutes * this.perMinute);
    this.lastRefill = now;
  }

  /** Milliseconds to wait before one token is available. */
  delayFor(cost = 1): number {
    this.refill();
    if (this.tokens >= cost) return 0;
    return Math.ceil(((cost - this.tokens) / this.perMinute) * 60_000);
  }

  take(cost = 1): void {
    this.refill();
    this.tokens = Math.max(0, this.tokens - cost);
  }

  /** Adopt the server's own count when it tells us. */
  resync(left: number): void {
    this.refill();
    this.tokens = Math.min(this.capacity, left);
  }

  get available(): number {
    this.refill();
    return Math.floor(this.tokens);
  }
}

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export class RateLimiter {
  private readonly buckets: Record<Bucket, TokenBucket>;
  /** Set when a 429 tells us to stand down until a wall-clock time. */
  private penaltyUntil = 0;

  constructor(readsPerMinute = LIMITS.readsPerMinute, writesPerMinute = LIMITS.writesPerMinute) {
    this.buckets = {
      read: new TokenBucket(readsPerMinute, readsPerMinute),
      write: new TokenBucket(writesPerMinute, writesPerMinute),
    };
  }

  /** Block until a token of this kind is available. */
  async acquire(bucket: Bucket): Promise<void> {
    const penalty = this.penaltyUntil - Date.now();
    if (penalty > 0) await sleep(penalty);

    const delay = this.buckets[bucket].delayFor();
    if (delay > 0) await sleep(delay);
    this.buckets[bucket].take();
  }

  /** Learn from the free "# budget:" footer on a normal reply. */
  observeBody(body: string): void {
    const match = BUDGET_FOOTER.exec(body);
    if (!match) return;
    const left = Number(match[1]);
    const kind = match[3]?.toLowerCase() === "write" ? "write" : "read";
    if (Number.isFinite(left)) this.buckets[kind].resync(left);
  }

  /** Back off for exactly as long as a 429 asked. */
  observe429(body: string, retryAfterHeader: string | null): void {
    let seconds = Number(retryAfterHeader);
    if (!Number.isFinite(seconds) || seconds <= 0) {
      const match = RETRY_SECONDS.exec(body);
      seconds = match ? Number(match[1]) : 5;
    }
    this.penaltyUntil = Date.now() + Math.ceil(seconds * 1000);
  }

  snapshot(): Record<Bucket, number> {
    return { read: this.buckets.read.available, write: this.buckets.write.available };
  }
}
