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
    case "rooms": {
      const { tendRooms } = await import("./agent/rooms.ts");
      return tendRooms();
    }
    case "capture": {
      const { captureSonnet } = await import("./agent/capture.ts");
      const dir = process.env.FLOP_ARCHIVE_DIR ?? "./archive/sonnet-2";
      // --daemon polls: the busiest rooms rotate in under two hours, so a
      // one-shot capture preserves only whatever happens to be in the ring.
      if (!args.includes("--daemon")) return void (await captureSonnet(dir));
      const everyMs = 15 * 60_000;
      for (;;) {
        try {
          await captureSonnet(dir);
        } catch (error) {
          console.log(`[!!] capture pass failed, continuing — ${error instanceof Error ? error.message : String(error)}`);
        }
        await new Promise((r) => setTimeout(r, everyMs));
      }
    }
    case "recruit": {
      const { recruitOnce } = await import("./agent/recruit.ts");
      return recruitOnce();
    }
    case "poach": {
      const { poachOnce } = await import("./agent/poach.ts");
      return poachOnce();
    }
    case "scout": {
      const { TechnocoreClient } = await import("./protocol/client.ts");
      const { findLegitTeams } = await import("./agent/scout.ts");
      const teams = await findLegitTeams(new TechnocoreClient());
      if (teams.length === 0) {
        console.log(`${new Date().toISOString()} no referee-validated team with an open seat`);
        return;
      }
      console.log(`${new Date().toISOString()} ${teams.length} referee-validated team(s) with seats:`);
      for (const t of teams.slice(0, 10)) {
        console.log(
          `  ${t.gameId.padEnd(20)} members=${t.members.length} seats=${t.seatsFree} gen=${t.generation} seq=${t.lastSeq}` +
            (t.lastReason ? ` lastRefereeReason="${t.lastReason}"` : ""),
        );
      }
      return;
    }
    case "offers": {
      const { TechnocoreClient } = await import("./protocol/client.ts");
      const { liveOffers } = await import("./agent/deal.ts");
      const offers = await liveOffers(new TechnocoreClient());
      const now = Date.now();
      console.log(`${offers.length} live paper-rail offers (longest claim window first)\n`);
      for (const o of offers.slice(0, 15)) {
        const job = (o.job ?? {}) as { proto?: unknown; id?: unknown };
        console.log(
          `  ${o.amount.padStart(9)} ${o.asset.padEnd(6)} claimBy ${String(Math.round((o.claimByMs - now) / 60000)).padStart(5)}m  ` +
            `${String(job.proto ?? "-").padEnd(13)} ${o.id.slice(0, 22)}...`,
        );
      }
      return;
    }
    case "deals": {
      const { loadDeals } = await import("./agent/deal.ts");
      const { deals } = loadDeals();
      if (deals.length === 0) {
        console.log("No deals accepted yet.");
        return;
      }
      for (const d of deals) {
        console.log(`${d.contract.slice(0, 22)}...  ${d.amount} ${d.asset}`);
        console.log(`   room ${d.room}`);
        console.log(`   accepted ${d.acceptedAt}${d.delivered ? ` | delivered ${d.delivered}` : ""}${d.revealed ? ` | revealed ${d.revealed}` : ""}`);
      }
      return;
    }
    case "accept": {
      const id = args[0];
      if (!id) {
        console.error("usage: flop accept <offer id>");
        process.exit(1);
      }
      const { acceptOffer } = await import("./agent/deal.ts");
      const deal = await acceptOffer(id);
      console.log(`accepted ${deal.offerId.slice(0, 22)}...`);
      console.log(`  contract ${deal.contract}`);
      console.log(`  deal room ${deal.room}`);
      console.log(`  ${deal.amount} ${deal.asset} from ${deal.counterparty.slice(0, 28)}...`);
      return;
    }
    case "deliver": {
      const [contract, ...rest] = args;
      if (!contract || rest.length === 0) {
        console.error("usage: flop deliver <contract> <text...>");
        process.exit(1);
      }
      const { deliverWork } = await import("./agent/deal.ts");
      await deliverWork(contract, rest.join(" "));
      console.log("delivered to the deal room");
      return;
    }
    case "reveal": {
      const contract = args[0];
      if (!contract) {
        console.error("usage: flop reveal <contract>");
        process.exit(1);
      }
      const { revealSecret } = await import("./agent/deal.ts");
      await revealSecret(contract);
      console.log("preimage revealed — claim published");
      return;
    }
    case "transcript": {
      const contract = args[0];
      if (!contract) {
        console.error("usage: flop transcript <contract>");
        process.exit(1);
      }
      const { dealTranscript } = await import("./agent/deal.ts");
      for (const f of await dealTranscript(contract)) {
        console.log(`  ${f.type.padEnd(9)} ${f.from.slice(0, 26)}... ${f.text.slice(0, 90)}`);
      }
      return;
    }
    case "post-offer": {
      const amount = args[0];
      const text = args.slice(1).join(" ");
      if (!amount || !text) {
        console.error('usage: flop post-offer <amount> <job description...>');
        process.exit(1);
      }
      const { postOffer } = await import("./agent/deal.ts");
      const posted = await postOffer({ amount, asset: "FLOP", jobText: text });
      console.log(`posted offer ${posted.offerId}`);
      console.log(`  ${posted.amount} ${posted.asset}, claim window closes ${new Date(posted.claimByMs).toISOString()}`);
      return;
    }
    case "owed": {
      const { acceptancesOfOurOffers } = await import("./agent/deal.ts");
      const list = await acceptancesOfOurOffers();
      if (list.length === 0) {
        console.log("Nobody has accepted our offers yet.");
        return;
      }
      for (const a of list) {
        console.log(`contract ${a.contract}`);
        console.log(`   accepted by ${a.from.slice(0, 30)}...  statement ${a.statement.slice(0, 18)}...`);
      }
      return;
    }
    case "lock": {
      const [contract, statement] = args;
      if (!contract || !statement) {
        console.error("usage: flop lock <contract> <statement>");
        process.exit(1);
      }
      const { lockDeal } = await import("./agent/deal.ts");
      await lockDeal(contract, statement);
      console.log("lock posted to the deal room");
      return;
    }
    case "seat": {
      const { watchSeatOnce } = await import("./agent/sonnet-watch.ts");
      await watchSeatOnce();
      return;
    }
    case "settle": {
      const { settleReadyDeals } = await import("./agent/deal.ts");
      const n = await settleReadyDeals();
      if (n === 0) console.log(`${new Date().toISOString()} no deals ready to reveal`);
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
      console.log("  capture [--daemon]     archive signed contest records before reclaim");
      console.log("  recruit                post one sonnet-team recruitment message");
      console.log("  health                 check notes, daemons, and key custody");
      console.log("  rooms                  hold room names, open them when a slot frees");
      console.log("  prove                  regenerate PROOF.md from live server state");
      process.exit(command ? 1 : 0);
  }
}

await main();
