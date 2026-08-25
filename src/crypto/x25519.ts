/**
 * Static X25519 keypair for the E2E pattern (patterns.md §4).
 *
 * Publishing an X25519 public key in the DID note is what lets a peer encrypt
 * a symmetric key to us without any prior contact — the server stores and
 * serves ciphertext and never sees a key. Almost no note in the live registry
 * carries one, which means almost no registered agent can actually be reached
 * privately.
 *
 * This key is separate from the Ed25519 identity key on purpose: signing keys
 * and key-agreement keys should not be the same key.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, type KeyObject } from "node:crypto";
import { join } from "node:path";
import { KEYS_DIR } from "../config.ts";

const X25519_FILE = "agent.x25519.pem";
const RAW_KEY_BYTES = 32;

const SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);

export interface X25519Keypair {
  publicKey: KeyObject;
  privateKey: KeyObject;
  rawPublicKey: Uint8Array;
  /** base64url, unpadded — the form published in the DID note. */
  publicKeyB64Url: string;
}

function rawPublicKeyFrom(publicKey: KeyObject): Uint8Array {
  const der = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  if (der.length !== SPKI_PREFIX.length + RAW_KEY_BYTES) {
    throw new Error(`unexpected SPKI length ${der.length}; not an X25519 public key`);
  }
  return new Uint8Array(der.subarray(SPKI_PREFIX.length));
}

function wrap(privateKey: KeyObject): X25519Keypair {
  const publicKey = createPublicKey(privateKey);
  const rawPublicKey = rawPublicKeyFrom(publicKey);
  return {
    publicKey,
    privateKey,
    rawPublicKey,
    publicKeyB64Url: Buffer.from(rawPublicKey).toString("base64url"),
  };
}

export function x25519Path(dir: string = KEYS_DIR): string {
  return join(dir, X25519_FILE);
}

/** Load the static X25519 key, generating and persisting it on first use. */
export function loadOrCreateX25519(dir: string = KEYS_DIR): X25519Keypair {
  const path = x25519Path(dir);

  if (existsSync(path)) {
    const mode = statSync(path).mode & 0o777;
    if (mode & 0o077) {
      throw new Error(`X25519 key at ${path} has permissions ${mode.toString(8)}; expected 600`);
    }
    return wrap(createPrivateKey({ key: readFileSync(path, "utf8"), format: "pem" }));
  }

  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const { privateKey } = generateKeyPairSync("x25519");
  writeFileSync(path, privateKey.export({ type: "pkcs8", format: "pem" }) as string, { mode: 0o600 });
  chmodSync(path, 0o600);
  return wrap(privateKey);
}

/** Rebuild an X25519 public KeyObject from raw bytes (for a peer's key). */
export function x25519PublicFromRaw(raw: Uint8Array): KeyObject {
  if (raw.length !== RAW_KEY_BYTES) {
    throw new Error(`raw X25519 public key must be ${RAW_KEY_BYTES} bytes, got ${raw.length}`);
  }
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

/** Raw ECDH shared secret. Feed this through HKDF before use as a key. */
export function sharedSecret(privateKey: KeyObject, peerPublicKey: KeyObject): Uint8Array {
  return new Uint8Array(diffieHellman({ privateKey, publicKey: peerPublicKey }));
}
