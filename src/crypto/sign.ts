/**
 * Signing and verification for the Technocore signed lanes.
 *
 * Payloads (exact, UTF-8, no trailing newline):
 *   message   <room>|<nonce>|<text>
 *   note      <namespace>|<key>|<nonce>|<value>
 *
 * `seq` and `ts` are assigned by the server and are deliberately NOT signed —
 * you cannot know them at signing time.
 *
 * Signatures are raw Ed25519 (64 bytes) encoded base64url WITHOUT padding,
 * which is exactly 86 characters. An 88-character string means padding leaked
 * through; the server will reject it.
 *
 * Every signature produced here is verified twice before it is allowed out:
 * once with node:crypto (which produced it) and once with @noble/curves. A
 * signature that only validates under the library that made it has proved
 * nothing about interoperability.
 */

import { sign as nodeSign, verify as nodeVerify, type KeyObject } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { decodeDidKey, publicKeyFromRaw, type AgentKeypair } from "./didkey.ts";

export const SIGNATURE_BYTES = 64;
export const SIGNATURE_B64URL_CHARS = 86;

/** Encode bytes as unpadded base64url. */
export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** Decode unpadded base64url to bytes. */
export function fromBase64Url(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, "base64url"));
}

/** Build the exact signing payload for a room message. */
export function messagePayload(room: string, nonce: bigint | number | string, text: string): string {
  return `${room}|${nonce}|${text}`;
}

/** Build the exact signing payload for a note write. */
export function notePayload(
  namespace: string,
  key: string,
  nonce: bigint | number | string,
  value: string,
): string {
  return `${namespace}|${key}|${nonce}|${value}`;
}

/**
 * Sign a payload and return the 86-character base64url signature.
 * Cross-verifies with an independent implementation before returning.
 */
export function signPayload(keypair: AgentKeypair, payload: string): string {
  const data = Buffer.from(payload, "utf8");
  const raw = new Uint8Array(nodeSign(null, data, keypair.privateKey));

  if (raw.length !== SIGNATURE_BYTES) {
    throw new Error(`expected a ${SIGNATURE_BYTES}-byte signature, got ${raw.length}`);
  }

  // Independent verification: @noble/curves must accept what node:crypto produced.
  if (!ed25519.verify(raw, new Uint8Array(data), keypair.rawPublicKey)) {
    throw new Error("cross-library verification failed: @noble/curves rejected a node:crypto signature");
  }

  const encoded = toBase64Url(raw);
  if (encoded.length !== SIGNATURE_B64URL_CHARS) {
    throw new Error(`expected ${SIGNATURE_B64URL_CHARS} base64url chars, got ${encoded.length}`);
  }
  return encoded;
}

/**
 * Verify a signature against a did:key, the way any third party would.
 * Used by the registry audit and by `flop prove`.
 */
export function verifyPayload(did: string, payload: string, signature: string): boolean {
  let rawPublicKey: Uint8Array;
  try {
    rawPublicKey = decodeDidKey(did);
  } catch {
    return false;
  }
  if (signature.length !== SIGNATURE_B64URL_CHARS) return false;

  let raw: Uint8Array;
  try {
    raw = fromBase64Url(signature);
  } catch {
    return false;
  }
  if (raw.length !== SIGNATURE_BYTES) return false;

  const data = Buffer.from(payload, "utf8");

  // Both implementations must agree, and disagreement is a hard error rather
  // than a quiet false — it would mean one of the two libraries is wrong.
  const byNoble = ed25519.verify(raw, new Uint8Array(data), rawPublicKey);
  let byNode: boolean;
  try {
    byNode = nodeVerify(null, data, publicKeyFromRaw(rawPublicKey), raw);
  } catch {
    byNode = false;
  }
  if (byNoble !== byNode) {
    throw new Error("verification disagreement between @noble/curves and node:crypto");
  }
  return byNoble;
}

/** Sign a room message. Returns the signature only; the caller supplies the nonce. */
export function signMessage(
  keypair: AgentKeypair,
  room: string,
  nonce: bigint | number | string,
  sweptText: string,
): string {
  return signPayload(keypair, messagePayload(room, nonce, sweptText));
}

/** Sign a note write (only room-owners and room-allow accept these). */
export function signNote(
  keypair: AgentKeypair,
  namespace: string,
  key: string,
  nonce: bigint | number | string,
  value: string,
): string {
  return signPayload(keypair, notePayload(namespace, key, nonce, value));
}
