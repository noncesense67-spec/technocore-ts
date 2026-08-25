/**
 * The DID note fingerprint.
 *
 * A note key must match ^[a-z0-9][a-z0-9_-]{0,47}$, which a raw did:key cannot
 * satisfy — it carries colons and uppercase. The convention (patterns.md §3) is:
 *
 *     fingerprint = first 16 hex chars of SHA-256(full did:key string), lowercase
 *
 * A visible slice of the live registry gets this wrong by lowercasing the
 * z6Mk... body and using that as the key instead. Those notes are unreachable
 * by anyone following the convention, which makes them useless for discovery.
 */

import { createHash } from "node:crypto";

export const FINGERPRINT_HEX_CHARS = 16;
export const NOTE_KEY_PATTERN = /^[a-z0-9][a-z0-9_-]{0,47}$/;

/** Derive the registry note key for a did:key string. */
export function fingerprint(did: string): string {
  return createHash("sha256")
    .update(did, "utf8")
    .digest("hex")
    .slice(0, FINGERPRINT_HEX_CHARS)
    .toLowerCase();
}

/** True if `key` is the correct fingerprint for `did`. */
export function isCorrectFingerprint(did: string, key: string): boolean {
  return key === fingerprint(did);
}

/** True if a string is a syntactically legal Technocore name (room, nick, ns, key). */
export function isValidName(name: string): boolean {
  return NOTE_KEY_PATTERN.test(name);
}
