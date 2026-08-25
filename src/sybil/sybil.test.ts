import { describe, expect, test } from "bun:test";
import { clusterByShape, normalise, shapeKey, type ObservedMessage } from "./cluster.ts";
import { band, conjunctionMultiplier, scoreIdentity, FLEET_SIGNALS } from "./score.ts";
import type { SignalContext } from "./signals.ts";

const iso = (msFromBase: number) => new Date(1_787_000_000_000 + msFromBase).toISOString();

/** One operator, many keys: shared template, tight burst, sequential counter. */
function fleet(size = 20): ObservedMessage[] {
  return Array.from({ length: size }, (_, i) => ({
    did: `did:key:zFleet${i}`,
    room: "lobby",
    seq: 1000 + i,
    ts: iso(i * 2_900), // ~2.9s apart, the cadence observed live
    text: `FLOP agent ${130 + i} check-in`,
    nonce: "1787616040857798049", // 19 digits, identical scheme
  }));
}

/**
 * Many operators, one starter kit: same phrasing, but independent schedules,
 * no shared counter. This population MUST score low — it is the false positive
 * the method exists to avoid.
 */
function sharedTooling(size = 20): ObservedMessage[] {
  return Array.from({ length: size }, (_, i) => ({
    did: `did:key:zIndie${i}`,
    room: "lobby",
    seq: 2000 + i,
    // Spread across days, not seconds.
    ts: iso(i * 7 * 3_600_000),
    text: `Hello from my agent, exploring the network today`,
    nonce: "1787616040857", // shared library, 13 digits
  }));
}

function contextFor(did: string, all: ObservedMessage[], extra: Partial<SignalContext> = {}): SignalContext {
  const clusters = clusterByShape(all);
  const mine = all.filter((m) => m.did === did);
  const cluster = clusters.find((c) => c.dids.has(did));
  return { did, messages: mine, cluster, ...extra };
}

describe("normalisation and clustering", () => {
  test("collapses scripted variants onto one shape", () => {
    expect(normalise("FLOP agent 74 check-in")).toBe(normalise("FLOP agent 212 check-in"));
    expect(shapeKey("FLOP agent 74 check-in")).toBe("flop agent # check in");
  });

  test("does not collapse genuinely different messages", () => {
    expect(shapeKey("Anyone working on inference routing?")).not.toBe(
      shapeKey("The fingerprint is sha256 of the did string"),
    );
  });

  test("ignores clusters of one and very short shapes", () => {
    const msgs: ObservedMessage[] = [
      { did: "a", room: "r", seq: 1, ts: iso(0), text: "a unique thought about compute markets" },
      { did: "b", room: "r", seq: 2, ts: iso(1), text: "ok" },
      { did: "c", room: "r", seq: 3, ts: iso(2), text: "ok" },
    ];
    expect(clusterByShape(msgs)).toHaveLength(0);
  });

  test("groups a fleet into one cluster", () => {
    const clusters = clusterByShape(fleet());
    expect(clusters).toHaveLength(1);
    expect(clusters[0]!.dids.size).toBe(20);
  });
});

describe("THE CLAIM: a fleet and shared tooling must be distinguishable", () => {
  test("a fleet scores high", () => {
    const all = fleet();
    const s = scoreIdentity(contextFor("did:key:zFleet5", all));
    expect(s.band).toBe("high");
    expect(s.fleetSignalsFired).toBeGreaterThanOrEqual(3);
  });

  test("shared tooling never reaches `high`, whatever its template match", () => {
    const all = sharedTooling();
    const s = scoreIdentity(contextFor("did:key:zIndie5", all));
    // The claim that matters. Same phrasing and the same nonce library, but
    // independent timing and no shared counter -> not a fleet finding.
    // It may land in `elevated`, which is the honest position: two signals
    // agree, and shared tooling explains exactly that.
    expect(s.band).not.toBe("high");
    expect(s.fleetSignalsFired).toBeLessThan(3);
  });

  test("`elevated` is actually reachable, not a dead band", () => {
    // A band that cannot fire collapses the method to binary and pushes
    // marginal cases into `high`. Assert the scale can produce all three.
    const s = scoreIdentity(contextFor("did:key:zIndie5", sharedTooling()));
    expect(s.fleetSignalsFired).toBe(2);
    expect(s.band).toBe("elevated");
    expect(band(0.9, 4)).toBe("high");
    expect(band(0.0, 0)).toBe("low");
  });

  test("the two populations are separated by a wide margin", () => {
    const f = scoreIdentity(contextFor("did:key:zFleet5", fleet())).score;
    const t = scoreIdentity(contextFor("did:key:zIndie5", sharedTooling())).score;
    expect(f).toBeGreaterThan(t * 2);
  });

  test("template match ALONE never reaches high", () => {
    // Strip every corroborating signal: same text, no counter, spread out.
    const all: ObservedMessage[] = Array.from({ length: 30 }, (_, i) => ({
      did: `did:key:zOnly${i}`,
      room: "lobby",
      seq: i,
      ts: iso(i * 6 * 3_600_000),
      text: "Exploring the network and reading the manual",
    }));
    const s = scoreIdentity(contextFor("did:key:zOnly3", all));
    expect(s.band).not.toBe("high");
  });

  test("an independent agent with real contributions scores low", () => {
    const all: ObservedMessage[] = [
      { did: "did:key:zReal", room: "lobby", seq: 1, ts: iso(0), text: "The did namespace is at its 5120 cap and refusing new keys" },
      { did: "did:key:zReal", room: "lobby", seq: 2, ts: iso(90_000), text: "Published an audit of every note in the registry today" },
      { did: "did:key:zReal", room: "lobby", seq: 3, ts: iso(200_000), text: "Retention is 604800 seconds and it applies to notes as well" },
    ];
    const s = scoreIdentity(contextFor("did:key:zReal", all, { hasContribution: true }));
    expect(s.band).toBe("low");
  });
});

describe("conjunction gate", () => {
  test("suppresses a lone signal hard", () => {
    expect(conjunctionMultiplier(0)).toBe(0.25);
    expect(conjunctionMultiplier(1)).toBe(0.25);
  });

  test("partially credits two, fully credits three or more", () => {
    expect(conjunctionMultiplier(2)).toBe(0.6);
    expect(conjunctionMultiplier(3)).toBe(1.0);
    expect(conjunctionMultiplier(5)).toBe(1.0);
  });

  test("no score can reach `high` on fewer than three fleet signals", () => {
    for (let fired = 0; fired < 3; fired++) {
      expect(band(1.0, fired)).not.toBe("high");
    }
    expect(band(0.9, 3)).toBe("high");
  });

  test("counts only fleet signals, not effort signals", () => {
    expect(FLEET_SIGNALS).not.toContain("contributionRatio");
    expect(FLEET_SIGNALS).not.toContain("lexicalRepetition");
  });
});

describe("scores are explainable", () => {
  test("every fired signal carries its evidence", () => {
    const s = scoreIdentity(contextFor("did:key:zFleet5", fleet()));
    expect(s.reasons.length).toBeGreaterThan(0);
    for (const r of s.reasons) expect(r).toMatch(/^[a-zA-Z]+: .+/);
  });

  test("a quiet identity produces no accusations", () => {
    const all: ObservedMessage[] = [
      { did: "did:key:zQuiet", room: "lobby", seq: 1, ts: iso(0), text: "Reading the protocol manual before writing anything" },
    ];
    const s = scoreIdentity(contextFor("did:key:zQuiet", all));
    expect(s.band).toBe("low");
    expect(s.reasons).toHaveLength(0);
  });
});
