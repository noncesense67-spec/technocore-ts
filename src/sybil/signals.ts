/**
 * Sybil signal extractors.
 *
 * Seven independent measurements over public data. Each returns a value in
 * 0..1 and the evidence behind it, so a score can always be explained rather
 * than merely asserted.
 *
 * Design rule: no single signal is meant to be conclusive. Several of them
 * have innocent explanations on their own — shared phrasing means shared
 * tooling, a common nonce scheme means a common library. Only their conjunction
 * distinguishes one operator holding many keys from many operators holding one
 * each, and enforcing that is score.ts's job, not this module's.
 */

import type { Cluster, ObservedMessage } from "./cluster.ts";
import { normalise } from "./cluster.ts";

export interface Signal {
  /** 0 = no indication, 1 = strong indication. */
  value: number;
  evidence: string;
}

export interface SignalContext {
  did: string;
  /** Messages from this identity. */
  messages: ObservedMessage[];
  /** The largest template cluster this identity belongs to, if any. */
  cluster?: Cluster;
  /** This identity's DID registry note, if published. */
  note?: string | null;
  /** Cluster-mates' notes, for structural comparison. */
  peerNotes?: string[];
  /** True if the identity has published anything to /kv/contrib. */
  hasContribution?: boolean;
}

const clamp = (n: number) => Math.max(0, Math.min(1, n));

/**
 * 1. Template share — how much of this identity's output is templated, scaled
 * by how many other identities share the template.
 */
export function templateShare(ctx: SignalContext): Signal {
  if (!ctx.cluster || ctx.messages.length === 0) {
    return { value: 0, evidence: "not in any multi-identity template cluster" };
  }
  const peers = ctx.cluster.dids.size;
  // Two identities sharing a phrase is coincidence; twenty is a template.
  const scale = clamp((peers - 2) / 18);
  return {
    value: scale,
    evidence: `template "${ctx.cluster.shape}" shared with ${peers - 1} other identities`,
  };
}

/**
 * 2. Burst correlation — does this identity post in lockstep with its
 * cluster-mates? Independent operators running the same tool drift apart;
 * one process iterating a key list does not.
 */
export function burstCorrelation(ctx: SignalContext): Signal {
  if (!ctx.cluster || ctx.messages.length === 0) {
    return { value: 0, evidence: "no cluster to correlate against" };
  }

  const others = ctx.cluster.messages.filter((m) => m.did !== ctx.did);
  if (others.length === 0) return { value: 0, evidence: "no cluster-mates observed" };

  const otherTimes = others.map((m) => Date.parse(m.ts)).sort((a, b) => a - b);
  const gaps: number[] = [];

  for (const m of ctx.messages) {
    const t = Date.parse(m.ts);
    let nearest = Infinity;
    for (const o of otherTimes) nearest = Math.min(nearest, Math.abs(o - t));
    if (Number.isFinite(nearest)) gaps.push(nearest / 1000);
  }
  if (gaps.length === 0) return { value: 0, evidence: "no comparable timestamps" };

  gaps.sort((a, b) => a - b);
  const median = gaps[Math.floor(gaps.length / 2)]!;

  // Under 10s from a cluster-mate is lockstep; beyond ~5 minutes is unrelated.
  const value = clamp((300 - median) / 290);
  return {
    value,
    evidence: `median ${median.toFixed(1)}s from the nearest cluster-mate post`,
  };
}

/**
 * 3. Sequential identity markers — an operator-side counter leaking into the
 * text. Scored on how densely the cluster fills its own numeric range, so a
 * handful of coincidental numbers does not register.
 */
export function sequentialMarker(ctx: SignalContext): Signal {
  const COUNTER = /\b(?:agent|node|bot|worker|instance)\s*#?\s*(\d{1,6})\b/i;

  const own = ctx.messages.map((m) => COUNTER.exec(m.text)?.[1]).filter(Boolean) as string[];
  if (own.length === 0) return { value: 0, evidence: "no counter-shaped identifier in messages" };

  if (!ctx.cluster) {
    return { value: 0.2, evidence: `counter "${own[0]}" present but no cluster to corroborate` };
  }

  const nums = ctx.cluster.messages
    .map((m) => COUNTER.exec(m.text)?.[1])
    .filter(Boolean)
    .map(Number) as number[];

  const distinct = new Set(nums);
  if (distinct.size < 3) return { value: 0.2, evidence: "too few counters to establish a range" };

  const lo = Math.min(...distinct);
  const hi = Math.max(...distinct);
  const span = hi - lo + 1;
  const density = distinct.size / span;

  return {
    value: clamp(density * 2),
    evidence: `${distinct.size} distinct counters spanning ${lo}-${hi} (density ${(density * 100).toFixed(0)}%), own=${own[0]}`,
  };
}

/**
 * 4. Nonce scheme fingerprint — 13 digits is a millisecond clock, 19 a
 * nanosecond one. Weak alone (a shared library explains it) but meaningful
 * when the whole cluster agrees.
 */
export function nonceHomogeneity(ctx: SignalContext): Signal {
  const own = ctx.messages.map((m) => String(m.nonce ?? "").length).filter((n) => n > 0);
  if (own.length === 0) return { value: 0, evidence: "no nonces observed" };

  const ownLen = own[0]!;
  if (!ctx.cluster) return { value: 0, evidence: `${ownLen}-digit nonce, no cluster to compare` };

  const peerLens = ctx.cluster.messages
    .filter((m) => m.did !== ctx.did)
    .map((m) => String(m.nonce ?? "").length)
    .filter((n) => n > 0);
  if (peerLens.length === 0) return { value: 0, evidence: "no peer nonces observed" };

  const matching = peerLens.filter((n) => n === ownLen).length / peerLens.length;
  return {
    value: clamp((matching - 0.5) * 2),
    evidence: `${ownLen}-digit nonce; ${(matching * 100).toFixed(0)}% of cluster-mates match`,
  };
}

/**
 * 5. Registry note homogeneity — identical field ordering across notes points
 * at one generator.
 */
export function noteHomogeneity(ctx: SignalContext): Signal {
  if (!ctx.note || !ctx.peerNotes?.length) {
    return { value: 0, evidence: "no note or no peer notes to compare" };
  }
  const skeleton = (n: string) =>
    n
      .trim()
      .split(/\s+/)
      .map((tok) => (tok.includes(":") ? tok.split(":")[0] : "@"))
      .join(" ");

  const own = skeleton(ctx.note);
  const matches = ctx.peerNotes.filter((p) => skeleton(p) === own).length;
  const share = matches / ctx.peerNotes.length;

  return {
    value: clamp((share - 0.5) * 2),
    evidence: `note skeleton "${own.slice(0, 60)}" matches ${(share * 100).toFixed(0)}% of peers`,
  };
}

/**
 * 6. Contribution ratio — output that is all presence and no artifact. This is
 * the signal that most rewards genuine work, so it is deliberately generous:
 * any published contribution zeroes it.
 */
export function contributionRatio(ctx: SignalContext): Signal {
  if (ctx.hasContribution) {
    return { value: 0, evidence: "has a published contribution note" };
  }
  const PRESENCE = /\b(check[- ]?in|checking in|online|alive|uptime|heartbeat|ping|present|standing by|booting)\b/i;
  const presence = ctx.messages.filter((m) => PRESENCE.test(m.text)).length;
  if (ctx.messages.length === 0) return { value: 0, evidence: "no messages observed" };

  const share = presence / ctx.messages.length;
  return {
    value: clamp(share),
    evidence: `${presence}/${ctx.messages.length} messages are presence announcements, no contribution note`,
  };
}

/**
 * 7. Lexical diversity — a real agent varies its output; a script repeats.
 * Only meaningful with several messages, so it stays neutral below that.
 */
export function lexicalRepetition(ctx: SignalContext): Signal {
  if (ctx.messages.length < 3) {
    return { value: 0, evidence: `only ${ctx.messages.length} message(s), not enough to judge` };
  }
  const shapes = new Set(ctx.messages.map((m) => normalise(m.text)));
  const ratio = shapes.size / ctx.messages.length;
  return {
    value: clamp(1 - ratio),
    evidence: `${shapes.size} distinct shapes across ${ctx.messages.length} messages`,
  };
}

export const SIGNALS = {
  templateShare,
  burstCorrelation,
  sequentialMarker,
  nonceHomogeneity,
  noteHomogeneity,
  contributionRatio,
  lexicalRepetition,
} as const;

export type SignalName = keyof typeof SIGNALS;
