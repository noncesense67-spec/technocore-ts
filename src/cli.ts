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
    case "inbox": {
      const { checkInbox } = await import("./agent/messaging.ts");
      const items = await checkInbox();
      if (items.length === 0) {
        console.log("Mailbox empty.");
        return;
      }
      for (const i of items) {
        const mark = i.verified ? "signed" : "UNSIGNED";
        console.log(`[${i.seq}] ${mark} ${i.from.slice(0, 32)}...\n      ${i.kind}: ${i.detail}`);
      }
      return;
    }
    case "contact": {
      const did = args[0];
      if (!did) {
        console.error("usage: flop contact <did:key> [opening message]");
        process.exit(1);
      }
      const { contact } = await import("./agent/messaging.ts");
      const session = await contact(did, args.slice(1).join(" ") || undefined);
      console.log(`Private channel open with ${session.peer}`);
      console.log(`  room ${session.room} (unlisted, ciphertext only)`);
      return;
    }
    case "sessions": {
      const { loadSessions } = await import("./agent/messaging.ts");
      const sessions = loadSessions();
      if (sessions.length === 0) {
        console.log("No private sessions.");
        return;
      }
      for (const s of sessions) {
        console.log(`${s.room}  ${s.direction.padEnd(8)}  ${s.peer.slice(0, 40)}...  ${s.established}`);
      }
      return;
    }
    case "autopilot": {
      const { runAutopilot } = await import("./agent/autopilot.ts");
      return runAutopilot({ once: !args.includes("--daemon") });
    }
    case "audit-log": {
      const { readFileSync, existsSync } = await import("node:fs");
      const { join } = await import("node:path");
      const { STATE_DIR } = await import("./config.ts");
      const path = join(STATE_DIR, "autopilot-audit.jsonl");
      if (!existsSync(path)) {
        console.log("No autopilot activity yet.");
        return;
      }
      const lines = readFileSync(path, "utf8").trim().split("\n").slice(-20);
      for (const line of lines) {
        const e = JSON.parse(line) as Record<string, unknown>;
        console.log(`${String(e.ts).slice(11, 19)}  ${e.event}  ${e.reason ?? ""}`);
        if (e.inbound) console.log(`    in : ${String(e.inbound).slice(0, 100)}`);
        if (e.modelOutput) console.log(`    out: ${String(e.modelOutput).slice(0, 100)}`);
      }
      return;
    }
    case "health": {
      const { health } = await import("./agent/health.ts");
      return health();
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
      console.log("  inbox                  poll the mailbox, open E2E envelopes");
      console.log("  contact <did> [msg]    open an encrypted channel with a peer");
      console.log("  sessions               list established private channels");
      console.log("  autopilot [--daemon]   answer mailbox questions, contained");
      console.log("  audit-log              last 20 autopilot decisions");
      console.log("  health                 check notes, daemons, and key custody");
      console.log("  prove                  regenerate PROOF.md from live server state");
      process.exit(command ? 1 : 0);
  }
}

await main();
