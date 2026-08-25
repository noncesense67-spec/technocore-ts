/**
 * The single-line sweep.
 *
 * The protocol stores one record per line, and replaces every invisible
 * character with a space before storage: C0/C1 controls (newline included),
 * Unicode format characters, zero-width joiners, bidi overrides.
 *
 * The signature must cover the text AFTER this sweep — the bytes that actually
 * get stored — so a record stays verifiable later. Sign the raw text instead
 * and the server will reject it. This is the single most common way an
 * otherwise-correct implementation fails.
 *
 * Two layers of defence here:
 *   1. `sweep()` models the server's transform, so we always sign stored bytes.
 *   2. `assertPrintableAscii()` constrains our own writes to a range where the
 *      sweep is provably a no-op, removing the failure class entirely rather
 *      than relying on our model of it being exact.
 *
 * The sweep is also a security control, not just a storage invariant: text that
 * renders as nothing is how instructions get smuggled into another agent's
 * context. See ../safety/sanitize.ts.
 */

/**
 * The sweep's six Unicode general categories, as a closed set:
 *
 *   Cc  C0/C1 controls, newline and tab included
 *   Cf  format characters — ZWJ, ZWNJ, ZWSP, soft hyphen, bidi overrides
 *       and isolates
 *   Cs  surrogates (lone halves of a surrogate pair)
 *   Co  private use
 *   Zl  line separator (U+2028)
 *   Zp  paragraph separator (U+2029)
 *
 * The manual illustrates this set with examples rather than naming it, which
 * makes `Cs`, `Co`, `Zl` and `Zp` easy to miss — the natural reading of "every
 * invisible character" is control characters, and a client written that way
 * passes every ASCII test you would think to write, then 403s on the first
 * zero-width space. Upstream flop-labs/technocore-chat#73 documents the closed
 * set; this mirrors it.
 */
export const INVISIBLE_PATTERN = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu;

/** Printable ASCII, space through tilde. The sweep cannot alter this range. */
export const PRINTABLE_ASCII_PATTERN = /^[\x20-\x7E]*$/;

/**
 * Apply the single-line sweep: every character in the six invisible categories
 * becomes one space, and THEN the ends are trimmed.
 *
 * The trim is not cosmetic — it runs after the replacement, so a message that
 * began with a newline loses the space that newline became. Sign the untrimmed
 * string and the signature covers bytes the server did not store.
 */
export function sweep(text: string): string {
  return text.replace(INVISIBLE_PATTERN, " ").trim();
}

/** True if the sweep would leave `text` byte-identical. */
export function isSweepNoop(text: string): boolean {
  return sweep(text) === text;
}

/** True if `text` is entirely printable ASCII. */
export function isPrintableAscii(text: string): boolean {
  return PRINTABLE_ASCII_PATTERN.test(text);
}

/**
 * Guard for outbound text. Throws rather than silently signing bytes that
 * differ from what the server will store.
 */
export function assertPrintableAscii(text: string, label = "text"): string {
  if (!isPrintableAscii(text)) {
    const offender = [...text].find((ch) => !isPrintableAscii(ch));
    const code = offender ? `U+${offender.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}` : "unknown";
    throw new Error(
      `${label} contains a non-printable-ASCII character (${code}); ` +
        `restrict outbound text to \\x20-\\x7E so the single-line sweep is a no-op`,
    );
  }
  return text;
}

/**
 * Canonicalise outbound text: sweep it, then assert the result is stable.
 * Returns exactly the bytes to sign and to send.
 */
export function canonicaliseOutbound(text: string, label = "text"): string {
  const swept = sweep(text);
  assertPrintableAscii(swept, label);
  return swept;
}
