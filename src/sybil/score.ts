/**
 * Composite scoring, and the conjunction rule that keeps it honest.
 *
 * The failure mode this guards against: a popular open-source starter kit
 * produces hundreds of identities that share phrasing, share a nonce library,
 * and share a note layout — while being hundreds of genuinely independent
 * operators. A naive weighted sum flags all of them, and publishing that would
 * defame people for the crime of using common tooling.
 *
 * So a high score requires several *independent* fleet signals to agree. One
 * signal firing has an innocent explanation almost every time. Template match
 * plus synchronised bursts plus a shared sequential counter does not.
 *
 * The output is evidence with a number attached, never a verdict. Nothing here
 * decides that an identity is a sybil; it decides that an identity is worth a
 * human looking at, and shows its working.
 */

import { SIGNALS, type Signal, type SignalContext, type SignalName } from "./signals.ts";

/**
 * Signals that speak to "one operator, many keys". These are the ones the
 * conjunction rule counts.
 */
export const FLEET_SIGNALS: SignalName[] = [
  "templateShare",
  "burstCorrelation",
  "sequentialMarker",
  "nonceHomogeneity",
  "noteHomogeneity",
];

/**
 * Signals that speak to "low-effort participation". Real information about
 * contribution quality, but NOT evidence of multiple identities, so they are
 * scored separately and cannot by themselves push an identity into a high band.
 */
export const EFFORT_SIGNALS: SignalName[] = ["contributionRatio", "lexicalRepetition"];

export const DEFAULT_WEIGHTS: Record<SignalName, number> = {
  templateShare: 1.0,
  burstCorrelation: 1.2,
  sequentialMarker: 1.5,
  nonceHomogeneity: 0.6,
  noteHomogeneity: 0.7,
  contributionRatio: 0.5,
  lexicalRepetition: 0.5,
};

/** A signal counts toward conjunction only above this. */
export const FIRE_THRESHOLD = 0.5;

export type Band = "low" | "elevated" | "high";

export interface Score {
  did: string;
  /** 0..1 composite, after the conjunction gate. */
  score: number;
  band: Band;
  /** How many independent fleet signals fired. This is the honest headline. */
  fleetSignalsFired: number;
  signals: Record<SignalName, Signal>;
  /** Human-readable reasons, strongest first. */
  reasons: string[];
}

/**
 * The gate. Fewer than two independent fleet signals means the evidence is
 * consistent with shared tooling, and the score is suppressed accordingly.
 */
export function conjunctionMultiplier(fired: number): number {
  if (fired <= 1) return 0.25;
  if (fired === 2) return 0.6;
  return 1.0;
}

export function scoreIdentity(
  ctx: SignalContext,
  weights: Record<SignalName, number> = DEFAULT_WEIGHTS,
): Score {
  const signals = Object.fromEntries(
    (Object.keys(SIGNALS) as SignalName[]).map((name) => [name, SIGNALS[name](ctx)]),
  ) as Record<SignalName, Signal>;

  const fired = FLEET_SIGNALS.filter((n) => signals[n].value >= FIRE_THRESHOLD).length;

  let weighted = 0;
  let total = 0;
  for (const name of Object.keys(SIGNALS) as SignalName[]) {
    weighted += signals[name].value * weights[name];
    total += weights[name];
  }

  const raw = total > 0 ? weighted / total : 0;
  const score = Math.max(0, Math.min(1, raw * conjunctionMultiplier(fired)));

  const reasons = (Object.keys(SIGNALS) as SignalName[])
    .filter((n) => signals[n].value >= FIRE_THRESHOLD)
    .sort((a, b) => signals[b].value * weights[b] - signals[a].value * weights[a])
    .map((n) => `${n}: ${signals[n].evidence}`);

  return {
    did: ctx.did,
    score,
    band: band(score, fired),
    fleetSignalsFired: fired,
    signals,
    reasons,
  };
}

/**
 * Bands.
 *
 * The count of agreeing signals is the honest headline, not the composite
 * number — so bands are gated primarily on conjunction, with the score as a
 * secondary floor. An identity can never reach `high` on one signal, however
 * extreme that signal is.
 *
 * Thresholds are calibrated against what the scale can actually produce. The
 * weighted mean divides by every weight, including signals that did not fire,
 * so two strong signals top out around 0.24 — an earlier 0.30 cut made
 * `elevated` mathematically unreachable and silently collapsed the method to
 * a binary, pushing every marginal case into `high`.
 *
 * What the bands mean, epistemically:
 *   low       nothing notable.
 *   elevated  two signals agree. Commonly explained by shared tooling —
 *             a starter kit produces template and nonce matches on its own.
 *             This is "worth a glance", not evidence of anything.
 *   high      three or more independent signals agree, including at least one
 *             that shared tooling does not produce (synchronised bursts, a
 *             sequential counter). This is "worth a human looking properly".
 */
export function band(score: number, fleetSignalsFired: number): Band {
  if (fleetSignalsFired >= 3 && score >= 0.35) return "high";
  if (fleetSignalsFired >= 2 && score >= 0.12) return "elevated";
  return "low";
}
