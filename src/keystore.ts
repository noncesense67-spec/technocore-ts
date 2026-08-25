/**
 * Private key custody.
 *
 * The key IS the airdrop address and the only durable claim to this identity.
 * There is no recovery: no account, no email, no reset. Losing the file loses
 * the identity, and disclosing it hands the identity away.
 *
 * Rules enforced here:
 *   - the key never leaves this machine and is never returned by any function
 *     that formats output for the network;
 *   - the file is written 0600 inside a 0700 directory, both gitignored;
 *   - loading refuses a key whose permissions are wider than 0600.
 *
 * The private key is stored as PKCS#8 PEM so standard tooling (openssl, ssh,
 * any Ed25519 library) can read it without this codebase.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createPrivateKey } from "node:crypto";
import { join } from "node:path";
import { KEYS_DIR } from "./config.ts";
import { fromPrivateKey, type AgentKeypair } from "./crypto/didkey.ts";
import { fingerprint } from "./crypto/fingerprint.ts";

const PRIVATE_KEY_FILE = "agent.ed25519.pem";
const PUBLIC_INFO_FILE = "agent.public.json";

export interface PublicIdentity {
  did: string;
  fingerprint: string;
  noteUrl: string;
  created: string;
  algorithm: "Ed25519";
}

export function keyPath(dir: string = KEYS_DIR): string {
  return join(dir, PRIVATE_KEY_FILE);
}

export function publicInfoPath(dir: string = KEYS_DIR): string {
  return join(dir, PUBLIC_INFO_FILE);
}

export function keyExists(dir: string = KEYS_DIR): boolean {
  return existsSync(keyPath(dir));
}

/** Persist a keypair. Refuses to overwrite an existing key. */
export function saveKeypair(keypair: AgentKeypair, dir: string = KEYS_DIR): PublicIdentity {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);

  const path = keyPath(dir);
  if (existsSync(path)) {
    throw new Error(`refusing to overwrite an existing key at ${path}`);
  }

  const pem = keypair.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  writeFileSync(path, pem, { mode: 0o600 });
  chmodSync(path, 0o600);

  const identity: PublicIdentity = {
    did: keypair.did,
    fingerprint: fingerprint(keypair.did),
    noteUrl: `/kv/did/${fingerprint(keypair.did)}`,
    created: new Date().toISOString(),
    algorithm: "Ed25519",
  };
  writeFileSync(publicInfoPath(dir), `${JSON.stringify(identity, null, 2)}\n`, { mode: 0o644 });
  return identity;
}

/** Load the agent keypair, refusing world- or group-readable key files. */
export function loadKeypair(dir: string = KEYS_DIR): AgentKeypair {
  const path = keyPath(dir);
  if (!existsSync(path)) {
    throw new Error(`no key at ${path} — run \`bun run flop keygen\` first`);
  }

  const mode = statSync(path).mode & 0o777;
  if (mode & 0o077) {
    throw new Error(
      `key at ${path} has permissions ${mode.toString(8)}; expected 600. ` +
        `Run: chmod 600 ${path}`,
    );
  }

  return fromPrivateKey(createPrivateKey({ key: readFileSync(path, "utf8"), format: "pem" }));
}

/** The public identity record, safe to print, publish, and commit. */
export function loadPublicIdentity(dir: string = KEYS_DIR): PublicIdentity | null {
  const path = publicInfoPath(dir);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as PublicIdentity;
}
