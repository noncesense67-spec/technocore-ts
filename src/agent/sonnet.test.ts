/**
 * The two rules that decide whether a sonnet can be entered at all.
 *
 * Both are counterintuitive in ways that punish judgement-by-ear, which is why
 * they are pinned here rather than trusted to a careful reader.
 */

import { describe, expect, test } from "bun:test";
import { canPlay, lettersOf, planPlay, wordLetters } from "./sonnet.ts";

const OURS = "did:key:z6MkpXLQhiDbEgBnBDCaD3vuZgaJGgH8H4YsShNsEw5dqsEw";

describe("letter rule", () => {
  test("a contributor may only spell words from its own did:key", () => {
    // Our DID carries no f, o, r, t — so the four commonest words in English
    // are all unplayable by us, and any plan that needs them needs a partner.
    for (const word of ["the", "to", "of", "for", "or", "from"]) {
      expect(canPlay(OURS, word)).toBe(false);
    }
    for (const word of ["I", "keep", "a", "key", "and", "line", "signed"]) {
      expect(canPlay(OURS, word)).toBe(true);
    }
  });

  test("punctuation is exempt; letters are matched case-insensitively", () => {
    expect(wordLetters("then,")).toEqual(["t", "h", "e", "n"]);
    expect(wordLetters("gate.")).toEqual(["g", "a", "t", "e"]);
    expect(lettersOf(OURS).has("z")).toBe(true);
    // 'Z' appears only uppercase in some DIDs; folding must catch it.
    expect(canPlay("did:key:zZZZ", "zz")).toBe(true);
  });
});

describe("turn planning", () => {
  const poem = ["a key and a key", "and a key and a"];

  test("a lone contributor cannot take consecutive turns", () => {
    const plan = planPlay(poem, [OURS]);
    expect(plan.ok).toBe(false);
  });

  test("two contributors can alternate", () => {
    const other = "did:key:zabcdefghijklmnopqrstuvwxyz";
    const plan = planPlay(poem, [OURS, other]);
    expect(plan.ok).toBe(true);
    // The real constraint: never the same DID twice in a row.
    for (let i = 1; i < plan.assignments.length; i++) {
      expect(plan.assignments[i]!.did).not.toBe(plan.assignments[i - 1]!.did);
    }
  });

  test("a word no member can spell is reported, not silently dropped", () => {
    // "for" needs f, o, r — none of which our DID carries.
    const plan = planPlay(["for"], [OURS]);
    expect(plan.ok).toBe(false);
    expect(plan.unplayable.map((u) => u.word)).toEqual(["for"]);
  });

  test("backtracks rather than stranding a scarce word", () => {
    // Both can play "ab", but only `rare` carries f/o/r/t. A greedy pass that
    // spends `rare` on "ab" strands "fort", because the next word may not be
    // played by the same member. The plan exists; finding it requires undoing
    // the first choice — which is exactly what kills a freestyling team, since
    // an accepted word can never be taken back.
    const rare = "did:key:zfortab";
    const common = "did:key:zabcdeghijklmnpqsuvwxyz";
    const plan = planPlay(["ab fort"], [rare, common]);
    expect(plan.ok).toBe(true);
    expect(plan.assignments.find((a) => a.word === "ab")!.did).toBe(common);
    expect(plan.assignments.find((a) => a.word === "fort")!.did).toBe(rare);
  });
});
