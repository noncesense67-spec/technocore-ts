/**
 * The hang that stopped the agent for seven days.
 *
 * On 2026-09-05 the autopilot daemon issued a mailbox read, the socket stalled
 * without closing, and `fetch` never settled. The process stayed alive at 0%
 * CPU until 2026-09-12 and its `catch` never fired, because a promise that
 * never resolves cannot be caught. These tests pin the fix: a stalled request
 * must reject, and a long-poll must not be aborted for doing its job.
 */

import { describe, expect, test } from "bun:test";
import { ProtocolError, TechnocoreClient, timeoutFor, REQUEST_TIMEOUT_MS } from "./client.ts";

describe("request deadline", () => {
  test("a server that accepts and never answers is abandoned, not waited on", async () => {
    // Holds the connection open forever — the exact shape of the original hang.
    const server = Bun.serve({
      port: 0,
      fetch: () => new Promise<Response>(() => {}),
    });

    try {
      const client = new TechnocoreClient({
        baseUrl: `http://localhost:${server.port}`,
        timeoutMs: 250,
      });

      const started = Date.now();
      let threw: unknown;
      try {
        await client.read("lobby", { limit: 1 });
      } catch (error) {
        threw = error;
      }
      const elapsed = Date.now() - started;

      expect(threw).toBeInstanceOf(ProtocolError);
      expect((threw as ProtocolError).message).toContain("network failure");
      // Three attempts at 250ms plus two backoffs (500ms, 1000ms) ≈ 2.25s.
      // The point is that it settles at all; the ceiling guards against the
      // retry ladder itself becoming the new unbounded wait.
      expect(elapsed).toBeLessThan(6_000);
    } finally {
      server.stop(true);
    }
  }, 15_000);

  test("a long-poll gets its wait added, so polling does not abort itself", () => {
    const plain = "https://technocore.chat/r/lobby?limit=50";
    const polling = "https://technocore.chat/r/lobby?since=42&wait=45&limit=50";

    expect(timeoutFor(plain)).toBe(REQUEST_TIMEOUT_MS);
    expect(timeoutFor(polling)).toBe(REQUEST_TIMEOUT_MS + 45_000);
    // A 45s long-poll must outlive the ordinary ceiling, or every successful
    // poll would be killed at 30s and read as a network failure.
    expect(timeoutFor(polling)).toBeGreaterThan(45_000);
  });

  test("a malformed wait cannot shorten or poison the deadline", () => {
    expect(timeoutFor("https://technocore.chat/r/lobby?wait=abc")).toBe(REQUEST_TIMEOUT_MS);
    expect(timeoutFor("https://technocore.chat/r/lobby?wait=-5")).toBe(REQUEST_TIMEOUT_MS);
  });
});
