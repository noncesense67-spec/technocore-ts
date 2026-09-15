/**
 * The recruitment text must actually be publishable.
 *
 * A rewrite of this pitch tripped our own outbound secret-shape guard: twelve
 * consecutive lowercase words look like a BIP-39 seed phrase to the heuristic,
 * so ordinary prose was refused at post time. The guard is right to be blunt —
 * the cost of missing real key material is unrecoverable — so the text bends,
 * not the guard. This test fails at build time instead of at 40-minute
 * intervals in a log nobody is reading.
 */

import { describe, expect, test } from "bun:test";
import { assertNoSecrets } from "../safety/sanitize.ts";
import { RECRUIT_TEXT, SONNET_DEADLINE_MS } from "./recruit.ts";
import { buildOffer } from "./poach.ts";
import { LIMITS } from "../config.ts";

describe("recruitment text", () => {
  test("passes the outbound secret-shape guard", () => {
    expect(() => assertNoSecrets(RECRUIT_TEXT, "recruit text")).not.toThrow();
  });

  test("fits in one message", () => {
    expect(RECRUIT_TEXT.length).toBeLessThanOrEqual(LIMITS.messageChars);
  });

  test("is printable ASCII so the server sweep cannot alter the signed bytes", () => {
    expect(/^[\x20-\x7E]*$/.test(RECRUIT_TEXT)).toBe(true);
  });

  test("names the deadline from the referee's signed launch record", () => {
    expect(SONNET_DEADLINE_MS).toBe(Date.parse("2026-09-18T12:00:00Z"));
  });
});

describe("seat offer", () => {
  const OURS = "did:key:z6MkpXLQhiDbEgBnBDCaD3vuZgaJGgH8H4YsShNsEw5dqsEw";
  const THEM = "did:key:z6MkmfTBoBXWXw5pQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";

  /**
   * The gap that cost a live opportunity: the recruitment text was tested, the
   * seat offer was not. It was refused at send time by our own secret-shape
   * guard and retried against a real unattached writer every two minutes,
   * failing silently each time. Every outbound text needs this, not just the
   * one that happened to break first.
   */
  test("is publishable — the guard is checked at build time, not at send time", () => {
    expect(() => buildOffer(THEM, OURS)).not.toThrow();
  });

  test("fits in one message", () => {
    expect(buildOffer(THEM, OURS).length).toBeLessThanOrEqual(LIMITS.messageChars);
  });

  test("is printable ASCII", () => {
    expect(/^[\x20-\x7E]*$/.test(buildOffer(THEM, OURS))).toBe(true);
  });
});
