/**
 * End-to-end encryption, implementing the choreography in patterns.md §4.
 *
 * The server is not involved and never sees a key: it stores ciphertext, serves
 * ciphertext, and that is the whole of its participation. What it does see is
 * sizes, timing, and the room name.
 *
 * Handshake (sender B contacting recipient A):
 *   1. B fetches A's DID note and reads `x25519:` and `mailbox:`
 *   2. B makes an EPHEMERAL X25519 keypair
 *   3. shared = HKDF-SHA256(X25519(eph_priv, A_static_pub), info="technocore-e2e-v1")
 *   4. B picks a fresh 32-byte room key K and an unguessable p-<name>
 *   5. sealed = AES-GCM(shared).encrypt(nonce12, K || room_name)
 *   6. B delivers one line to A's mailbox over the SIGNED lane:
 *          e2e1 <eph_pub> <nonce12> <sealed>          (all base64url, unpadded)
 *   7. A reverses it with its static private key and recovers K and the room
 *   Both then write  <nonce12>.<ct>  lines into the p- room, AES-GCM under K,
 *   with no AAD.
 *
 * What this buys, precisely: the operator sees ciphertext, not plaintext and not
 * keys. Authenticity rides on the DID note plus the signed mailbox delivery — an
 * unsigned key advertisement is, as the manual puts it, a nickname wearing math.
 * So `openEnvelope` tells you what was said and nothing about who said it; the
 * caller must check that the mailbox line was signed by a key it trusts.
 */

import { createCipheriv, createDecipheriv, generateKeyPairSync, hkdfSync, randomBytes } from "node:crypto";
import { sharedSecret, x25519PublicFromRaw } from "./x25519.ts";
import type { X25519Keypair } from "./x25519.ts";

const HKDF_INFO = "technocore-e2e-v1";
const ENVELOPE_TAG = "e2e1";
const KEY_BYTES = 32;
const GCM_NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));

/** Derive the wrapping key from a raw ECDH secret. */
function deriveWrappingKey(secret: Uint8Array): Uint8Array {
  // Salt is empty: both sides must derive identically and there is no shared
  // salt to agree on before the handshake exists.
  return new Uint8Array(hkdfSync("sha256", secret, new Uint8Array(0), HKDF_INFO, KEY_BYTES));
}

/** AES-256-GCM seal. Returns ciphertext with the 16-byte tag appended. */
export function seal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return new Uint8Array(Buffer.concat([body, cipher.getAuthTag()]));
}

/** AES-256-GCM open. Throws if the tag does not authenticate. */
export function open(key: Uint8Array, nonce: Uint8Array, sealed: Uint8Array): Uint8Array {
  if (sealed.length < GCM_TAG_BYTES) throw new Error("ciphertext is shorter than the GCM tag");
  const split = sealed.length - GCM_TAG_BYTES;
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(sealed.subarray(split));
  return new Uint8Array(Buffer.concat([decipher.update(sealed.subarray(0, split)), decipher.final()]));
}

export interface Envelope {
  /** The single line to deliver to the recipient's mailbox, signed. */
  line: string;
  /** The symmetric room key. Keep it; it is not recoverable from the line. */
  roomKey: Uint8Array;
  /** The unguessable room both parties will write ciphertext into. */
  room: string;
}

/**
 * Build a handshake envelope for a recipient's published X25519 key.
 * `room` defaults to a fresh unguessable p- name.
 */
export function sealEnvelope(recipientX25519PublicKey: Uint8Array, room?: string): Envelope {
  const roomName = room ?? `p-${randomBytes(16).toString("hex")}`;
  const roomKey = new Uint8Array(randomBytes(KEY_BYTES));

  // Ephemeral, per-handshake. Forward secrecy for the room key against later
  // compromise of the sender's long-term material.
  const { privateKey: ephPriv, publicKey: ephPub } = generateKeyPairSync("x25519");
  const ephPubRaw = new Uint8Array(
    (ephPub.export({ type: "spki", format: "der" }) as Buffer).subarray(12),
  );

  const wrapping = deriveWrappingKey(
    sharedSecret(ephPriv, x25519PublicFromRaw(recipientX25519PublicKey)),
  );

  const nonce = new Uint8Array(randomBytes(GCM_NONCE_BYTES));
  const plaintext = new Uint8Array(KEY_BYTES + Buffer.byteLength(roomName, "utf8"));
  plaintext.set(roomKey, 0);
  plaintext.set(new Uint8Array(Buffer.from(roomName, "utf8")), KEY_BYTES);

  const sealed = seal(wrapping, nonce, plaintext);

  return {
    line: `${ENVELOPE_TAG} ${b64(ephPubRaw)} ${b64(nonce)} ${b64(sealed)}`,
    roomKey,
    room: roomName,
  };
}

export interface OpenedEnvelope {
  roomKey: Uint8Array;
  room: string;
}

/**
 * Open a handshake envelope with our static X25519 key.
 *
 * Returns only what was sealed. It proves the sender held our published public
 * key, which everyone can read — it proves nothing about who they are. Identity
 * comes from the signature on the mailbox line, checked separately.
 */
export function openEnvelope(ours: X25519Keypair, line: string): OpenedEnvelope {
  const parts = line.trim().split(/\s+/);
  if (parts.length !== 4 || parts[0] !== ENVELOPE_TAG) {
    throw new Error(`not an ${ENVELOPE_TAG} envelope`);
  }

  const [, ephPubB64, nonceB64, sealedB64] = parts as [string, string, string, string];
  const ephPub = unb64(ephPubB64);
  if (ephPub.length !== KEY_BYTES) throw new Error("ephemeral public key is not 32 bytes");

  const nonce = unb64(nonceB64);
  if (nonce.length !== GCM_NONCE_BYTES) throw new Error("nonce is not 12 bytes");

  const wrapping = deriveWrappingKey(sharedSecret(ours.privateKey, x25519PublicFromRaw(ephPub)));
  const plaintext = open(wrapping, nonce, unb64(sealedB64));

  if (plaintext.length <= KEY_BYTES) throw new Error("envelope carried no room name");
  return {
    roomKey: plaintext.subarray(0, KEY_BYTES),
    room: Buffer.from(plaintext.subarray(KEY_BYTES)).toString("utf8"),
  };
}

/** Encrypt one room line under the shared room key: <nonce12>.<ct> */
export function sealLine(roomKey: Uint8Array, plaintext: string): string {
  const nonce = new Uint8Array(randomBytes(GCM_NONCE_BYTES));
  const sealed = seal(roomKey, nonce, new Uint8Array(Buffer.from(plaintext, "utf8")));
  return `${b64(nonce)}.${b64(sealed)}`;
}

/** Decrypt one room line. Throws if it does not authenticate under this key. */
export function openLine(roomKey: Uint8Array, line: string): string {
  const [nonceB64, sealedB64] = line.trim().split(".");
  if (!nonceB64 || !sealedB64) throw new Error("malformed ciphertext line");
  const nonce = unb64(nonceB64);
  if (nonce.length !== GCM_NONCE_BYTES) throw new Error("nonce is not 12 bytes");
  return Buffer.from(open(roomKey, nonce, unb64(sealedB64))).toString("utf8");
}

/** True if a line looks like a handshake envelope. */
export function isEnvelope(line: string): boolean {
  return line.trim().startsWith(`${ENVELOPE_TAG} `);
}

/**
 * Largest plaintext that still fits the 4096-char message cap once encrypted.
 * base64url of (12 nonce) and (n + 16 tag), plus the separating dot. Measured
 * rather than assumed, because "split before encrypting" is only actionable if
 * you know where to split.
 */
export function maxPlaintextBytes(messageCharCap = 4096): number {
  const nonceChars = Math.ceil((GCM_NONCE_BYTES * 4) / 3);
  const budget = messageCharCap - nonceChars - 1;
  return Math.floor((budget * 3) / 4) - GCM_TAG_BYTES;
}
