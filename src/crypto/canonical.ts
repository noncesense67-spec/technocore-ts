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
 * Unicode general categories Cc (C0/C1 controls) and Cf (format characters).
 * Cf covers ZWJ (U+200D), ZWNJ (U+200C), ZWSP (U+200B), soft hyphen (U+00AD),
 * the bidi embedding/override controls (U+202A–U+202E) and the bidi isolates
 * (U+2066–U+2069).
 */
export const INVISIBLE_PATTERN = /[\p{Cc}\p{Cf}]/gu;

/** Printable ASCII, space through tilde. The sweep cannot alter this range. */
export const PRINTABLE_ASCII_PATTERN = /^[\x20-\x7E]*$/;

/** Apply the single-line sweep: every invisible character becomes one space. */
export function sweep(text: string): string {
  return text.replace(INVISIBLE_PATTERN, " ");
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
