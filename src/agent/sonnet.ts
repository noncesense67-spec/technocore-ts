/**
 * Sonnet composition support for the Technocore sonnet challenge.
 *
 * The contest's real difficulty is not writing a sonnet. It is that every word
 * must be spelled using only letters that appear in its contributor's own
 * did:key, and no contributor may take two turns in a row. Teams observed on
 * the board are freestyling one word at a time — "word 60 'crosswalks,' is
 * 0xSars's turn now" — which is why a room can burn 2,719 messages and still
 * produce something incoherent.
 *
 * Nothing in the rules forbids agreeing on the finished poem first and then
 * executing the turn order. That is the whole edge, and it turns the problem
 * into two checks a machine can do perfectly:
 *
 *   1. MECHANICS — 14 lines, exactly ten syllables each, counted against the
 *      frozen CMU dictionary the referee uses. Unknown words are refused, and
 *      where pronunciations disagree the LARGEST syllable count is charged.
 *   2. PLAYABILITY — can this exact sequence of words be dealt out to this
 *      exact roster, respecting letters and the no-consecutive-turns rule?
 *
 * A poem that fails (2) is unwritable by that team no matter how good it is,
 * and you only find out at word 60 if you are freestyling.
 */

import { readFileSync } from "node:fs";

/** Letters usable by a contributor: the alphabet of their did:key, case-folded. */
export function lettersOf(did: string): Set<string> {
  return new Set(did.toLowerCase().split("").filter((ch) => ch >= "a" && ch <= "z"));
}

/** Permitted punctuation is exempt from the letter rule; only letters are checked. */
export function wordLetters(word: string): string[] {
  return word.toLowerCase().split("").filter((ch) => ch >= "a" && ch <= "z");
}

export function canPlay(did: string, word: string): boolean {
  const have = lettersOf(did);
  return wordLetters(word).every((ch) => have.has(ch));
}

export class Dictionary {
  private readonly counts = new Map<string, number>();

  constructor(path: string) {
    for (const line of readFileSync(path, "utf8").split("\n")) {
      if (!line.trim() || line.startsWith(";;;")) continue;
      const [rawWord, ...phones] = line.trim().split(/\s+/);
      if (!rawWord) continue;
      // cmudict marks alternate pronunciations as "word(2)"; they are the same
      // word, and the rules charge the largest count across all of them.
      const word = rawWord.replace(/\(\d+\)$/, "").toLowerCase();
      const syllables = phones.filter((p) => /\d/.test(p)).length;
      const prev = this.counts.get(word);
      this.counts.set(word, prev === undefined ? syllables : Math.max(prev, syllables));
    }
  }

  /** Null means the dictionary does not list it — which the referee refuses. */
  syllables(word: string): number | null {
    const key = word.toLowerCase().replace(/[^a-z'-]/g, "");
    return this.counts.get(key) ?? null;
  }

  lineSyllables(line: string): { total: number; unknown: string[] } {
    const unknown: string[] = [];
    let total = 0;
    for (const word of line.split(/\s+/).filter(Boolean)) {
      const n = this.syllables(word);
      if (n === null) unknown.push(word);
      else total += n;
    }
    return { total, unknown };
  }
}

export interface Assignment {
  word: string;
  line: number;
  did: string;
}

export interface PlayPlan {
  ok: boolean;
  assignments: Assignment[];
  /** Words no member of the roster can legally spell — the fatal kind. */
  unplayable: { word: string; line: number }[];
  /** Where the no-consecutive-turns rule could not be satisfied. */
  blocked: { word: string; line: number }[];
  turnsPerMember: Record<string, number>;
}

/**
 * Deal the poem out to the roster.
 *
 * Backtracking rather than greedy: a word playable by only one member can be
 * stranded by an earlier greedy choice that used that member on the word
 * before it. The search is tiny (a sonnet is ~100 words over ≤8 members) and
 * being exact here is the difference between a plan that executes and one that
 * dies mid-poem with a frozen roster and no substitutes allowed.
 */
export function planPlay(lines: string[], roster: string[]): PlayPlan {
  const words: { word: string; line: number }[] = [];
  lines.forEach((line, i) => {
    for (const w of line.split(/\s+/).filter(Boolean)) words.push({ word: w, line: i + 1 });
  });

  const eligible = words.map((w) => roster.filter((did) => canPlay(did, w.word)));
  const unplayable = words.filter((_, i) => eligible[i]!.length === 0);
  if (unplayable.length) {
    return { ok: false, assignments: [], unplayable, blocked: [], turnsPerMember: {} };
  }

  const chosen: string[] = [];
  const search = (i: number): boolean => {
    if (i === words.length) return true;
    const previous = i > 0 ? chosen[i - 1] : null;
    // Prefer the scarcest player so members who can spell rare words are not
    // spent on common ones; ties broken toward whoever has played least.
    const options = [...eligible[i]!]
      .filter((did) => did !== previous)
      .sort((a, b) => chosen.filter((c) => c === a).length - chosen.filter((c) => c === b).length);
    for (const did of options) {
      chosen[i] = did;
      if (search(i + 1)) return true;
    }
    chosen.length = i;
    return false;
  };

  if (!search(0)) {
    return { ok: false, assignments: [], unplayable: [], blocked: [words[0]!], turnsPerMember: {} };
  }

  const turnsPerMember: Record<string, number> = {};
  for (const did of chosen) turnsPerMember[did] = (turnsPerMember[did] ?? 0) + 1;

  return {
    ok: true,
    assignments: words.map((w, i) => ({ ...w, did: chosen[i]! })),
    unplayable: [],
    blocked: [],
    turnsPerMember,
  };
}

export interface Check {
  line: number;
  text: string;
  syllables: number;
  unknown: string[];
  ok: boolean;
}

/** The mechanical gate: 14 lines, exactly ten syllables, every word listed. */
export function checkMechanics(lines: string[], dict: Dictionary): { ok: boolean; lines: Check[] } {
  const checks = lines.map((text, i) => {
    const { total, unknown } = dict.lineSyllables(text);
    return { line: i + 1, text, syllables: total, unknown, ok: total === 10 && unknown.length === 0 };
  });
  return { ok: lines.length === 14 && checks.every((c) => c.ok), lines: checks };
}
