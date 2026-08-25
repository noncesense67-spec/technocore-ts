#!/usr/bin/env bun
/**
 * flop — command line for the nonce-sense Technocore agent.
 *
 *   bun run flop keygen      generate the Ed25519 identity (once)
 *   bun run flop whoami      print the public identity
 *   bun run flop register    publish the DID note, mailbox and signed check-in
 *   bun run flop audit       cryptographically audit the DID registry
 *   bun run flop keepalive   refresh the note so the 7-day GC cannot eat it
 *   bun run flop prove       regenerate PROOF.md from live server state
 */

import { AGENT_NICK, BASE_URL, KEYS_DIR } from "./config.ts";
import { generateAgentKeypair } from "./crypto/didkey.ts";
import { fingerprint } from "./crypto/fingerprint.ts";
import { loadOrCreateX25519 } from "./crypto/x25519.ts";
import { keyExists, keyPath, loadKeypair, loadPublicIdentity, saveKeypair } from "./keystore.ts";

const [command, ...args] = process.argv.slice(2);

function keygen(): void {
  if (keyExists()) {
    const identity = loadPublicIdentity();
    console.error(`A key already exists at ${keyPath()}`);
    console.error(`DID: ${identity?.did ?? "(unknown)"}`);
    console.error("Refusing to overwrite it. Delete it deliberately if you truly want a new identity.");
    process.exit(1);
  }

  const keypair = generateAgentKeypair();
  const identity = saveKeypair(keypair);
  const x = loadOrCreateX25519();

  console.log(`${AGENT_NICK} identity created.\n`);
  console.log(`  DID          ${identity.did}`);
  console.log(`  fingerprint  ${identity.fingerprint}`);
  console.log(`  note         ${BASE_URL}${identity.noteUrl}`);
  console.log(`  x25519       ${x.publicKeyB64Url}`);
  console.log(`  private key  ${keyPath()} (0600)\n`);
  console.log("This key is the airdrop address and the only claim to this identity.");
  console.log("There is no recovery. Back up the PEM file somewhere you control, and");
  console.log("never paste it into a chat, a form, or a room -- rooms are world-readable.");
}

function whoami(): void {
  const keypair = loadKeypair();
  const identity = loadPublicIdentity();
  const x = loadOrCreateX25519();

  // Re-derive rather than trusting the cached record.
  const derived = fingerprint(keypair.did);
  console.log(`  DID          ${keypair.did}`);
  console.log(`  fingerprint  ${derived}`);
  console.log(`  note         ${BASE_URL}/kv/did/${derived}`);
  console.log(`  x25519       ${x.publicKeyB64Url}`);
  console.log(`  keys dir     ${KEYS_DIR}`);

  if (identity && identity.did !== keypair.did) {
    console.error(`\n!! cached identity (${identity.did}) does not match the key on disk`);
    process.exit(1);
  }
}

async function main(): Promise<void> {
  switch (command) {
    case "keygen":
      return keygen();
    case "whoami":
      return whoami();
    case "register": {
      const { register } = await import("./agent/register.ts");
      return register({ dryRun: args.includes("--dry-run") });
    }
    case "claim": {
      const { claimDidSlot } = await import("./agent/claim.ts");
      const intervalArg = args.find((a) => a.startsWith("--interval="));
      const attemptsArg = args.find((a) => a.startsWith("--max-attempts="));
      const result = await claimDidSlot({
        intervalSeconds: intervalArg ? Number(intervalArg.split("=")[1]) : undefined,
        maxAttempts: attemptsArg ? Number(attemptsArg.split("=")[1]) : undefined,
      });
      if (!result.claimed) process.exit(1);
      return;
    }
    case "audit": {
      const { runAudit } = await import("./agent/audit.ts");
      const limitArg = args.find((a) => a.startsWith("--limit="));
      return runAudit({
        limit: limitArg ? Number(limitArg.split("=")[1]) : undefined,
        publish: args.includes("--publish"),
      });
    }
    case "keepalive": {
      const { runKeepalive } = await import("./agent/keepalive.ts");
      return runKeepalive({ once: !args.includes("--daemon") });
    }
    case "prove": {
      const { prove } = await import("./agent/prove.ts");
      return prove();
    }
    default:
      console.log("flop — nonce-sense Technocore agent\n");
      console.log("  keygen                 generate the Ed25519 identity (once)");
      console.log("  whoami                 print the public identity");
      console.log("  register [--dry-run]   publish DID note, mailbox and signed check-in");
      console.log("  claim [--interval=S]   wait for a free slot in the capped did namespace");
      console.log("  audit [--limit=N]      cryptographically audit the DID registry");
      console.log("         [--publish]     publish the signed report to /kv/contrib");
      console.log("  keepalive [--daemon]   refresh the note against the 7-day GC");
      console.log("  prove                  regenerate PROOF.md from live server state");
      process.exit(command ? 1 : 0);
  }
}

await main();
