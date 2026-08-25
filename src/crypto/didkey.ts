/**
 * did:key encoding for Ed25519, per the W3C did:key method and multiformats.
 *
 * The chain is: raw 32-byte public key
 *   -> prepend the ed25519-pub multicodec varint (0xed 0x01)
 *   -> base58btc encode the resulting 34 bytes
 *   -> prepend the multibase prefix 'z'
 *   -> prepend "did:key:"
 *
 * The 0xed multicodec encoded as an unsigned varint is the TWO bytes 0xed 0x01,
 * not the single byte 0xed. Getting that wrong still produces a plausible-looking
 * z-string, which is why several notes in the live registry are malformed.
 */

import { generateKeyPairSync, createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { base58 } from "@scure/base";

/** ed25519-pub multicodec (0xed) as an unsigned varint. */
export const ED25519_PUB_MULTICODEC = Uint8Array.from([0xed, 0x01]);

/** Raw Ed25519 key sizes, in bytes. */
export const RAW_PUBLIC_KEY_BYTES = 32;
export const RAW_PRIVATE_KEY_BYTES = 32;

/** Fixed DER preambles for Ed25519. The raw key is the tail after these bytes. */
const SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

export const DID_KEY_PATTERN = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/;

export interface AgentKeypair {
  did: string;
  rawPublicKey: Uint8Array;
  rawPrivateKey: Uint8Array;
  publicKey: KeyObject;
  privateKey: KeyObject;
}

/** Extract the raw 32-byte public key from a Node KeyObject via its SPKI DER encoding. */
export function rawPublicKeyFrom(publicKey: KeyObject): Uint8Array {
  const der = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  if (der.length !== SPKI_PREFIX.length + RAW_PUBLIC_KEY_BYTES) {
    throw new Error(`unexpected SPKI length ${der.length}; not an Ed25519 public key`);
  }
  return new Uint8Array(der.subarray(SPKI_PREFIX.length));
}

/** Extract the raw 32-byte seed from a Node KeyObject via its PKCS8 DER encoding. */
export function rawPrivateKeyFrom(privateKey: KeyObject): Uint8Array {
  const der = privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
  if (der.length !== PKCS8_PREFIX.length + RAW_PRIVATE_KEY_BYTES) {
    throw new Error(`unexpected PKCS8 length ${der.length}; not an Ed25519 private key`);
  }
  return new Uint8Array(der.subarray(PKCS8_PREFIX.length));
}

/** Rebuild a Node private KeyObject from a raw 32-byte Ed25519 seed. */
export function privateKeyFromRaw(raw: Uint8Array): KeyObject {
  if (raw.length !== RAW_PRIVATE_KEY_BYTES) {
    throw new Error(`raw private key must be ${RAW_PRIVATE_KEY_BYTES} bytes, got ${raw.length}`);
  }
  const der = Buffer.concat([PKCS8_PREFIX, raw]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Rebuild a Node public KeyObject from a raw 32-byte Ed25519 public key. */
export function publicKeyFromRaw(raw: Uint8Array): KeyObject {
  if (raw.length !== RAW_PUBLIC_KEY_BYTES) {
    throw new Error(`raw public key must be ${RAW_PUBLIC_KEY_BYTES} bytes, got ${raw.length}`);
  }
  const der = Buffer.concat([SPKI_PREFIX, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

/** Encode a raw 32-byte Ed25519 public key as a did:key string. */
export function encodeDidKey(rawPublicKey: Uint8Array): string {
  if (rawPublicKey.length !== RAW_PUBLIC_KEY_BYTES) {
    throw new Error(`raw public key must be ${RAW_PUBLIC_KEY_BYTES} bytes, got ${rawPublicKey.length}`);
  }
  const multicodec = new Uint8Array(ED25519_PUB_MULTICODEC.length + rawPublicKey.length);
  multicodec.set(ED25519_PUB_MULTICODEC, 0);
  multicodec.set(rawPublicKey, ED25519_PUB_MULTICODEC.length);
  return `did:key:z${base58.encode(multicodec)}`;
}

/**
 * Decode a did:key string back to its raw 32-byte public key.
 * Rejects anything that is not a well-formed Ed25519 did:key — this is the
 * validation the registry audit runs against every published note.
 */
export function decodeDidKey(did: string): Uint8Array {
  if (!did.startsWith("did:key:")) throw new Error("missing did:key: prefix");
  const multibase = did.slice("did:key:".length);
  if (!multibase.startsWith("z")) throw new Error("missing multibase 'z' (base58btc) prefix");

  let decoded: Uint8Array;
  try {
    decoded = base58.decode(multibase.slice(1));
  } catch {
    throw new Error("invalid base58btc payload");
  }

  if (decoded.length !== ED25519_PUB_MULTICODEC.length + RAW_PUBLIC_KEY_BYTES) {
    throw new Error(`expected 34 multicodec bytes, got ${decoded.length}`);
  }
  if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
    const got = `0x${decoded[0]?.toString(16)} 0x${decoded[1]?.toString(16)}`;
    throw new Error(`multicodec is ${got}, not ed25519-pub (0xed 0x01)`);
  }
  return decoded.subarray(ED25519_PUB_MULTICODEC.length);
}

/** True if `did` is a structurally valid Ed25519 did:key. */
export function isValidDidKey(did: string): boolean {
  try {
    decodeDidKey(did);
    return true;
  } catch {
    return false;
  }
}

/** Generate a fresh Ed25519 identity. */
export function generateAgentKeypair(): AgentKeypair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return fromPrivateKey(privateKey);
}

/** Rebuild a full keypair from a private KeyObject. */
export function fromPrivateKey(privateKey: KeyObject): AgentKeypair {
  const publicKey = createPublicKey(privateKey);
  const rawPublicKey = rawPublicKeyFrom(publicKey);
  return {
    did: encodeDidKey(rawPublicKey),
    rawPublicKey,
    rawPrivateKey: rawPrivateKeyFrom(privateKey),
    publicKey,
    privateKey,
  };
}

/** Rebuild a full keypair from a raw 32-byte seed. */
export function fromRawPrivateKey(raw: Uint8Array): AgentKeypair {
  return fromPrivateKey(privateKeyFromRaw(raw));
}
