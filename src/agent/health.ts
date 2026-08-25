/**
 * Health check.
 *
 * The failure this exists to catch is the quiet one: a daemon dies, nothing
 * complains, and the registration is reclaimed a week later. Our own audit
 * criticised 468 notes for failing silently — the same standard applies here.
 *
 * Every check names what it would mean if it failed, rather than printing a
 * status nobody can interpret.
 */

import { execSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { CONTRIB_NAMESPACE, DID_NAMESPACE, LIMITS, STATE_DIR } from "../config.ts";
import { TechnocoreClient } from "../protocol/client.ts";
import { fingerprint } from "../crypto/fingerprint.ts";
import { loadKeypair } from "../keystore.ts";
import { hasEverClaimed } from "./claim.ts";

interface Check {
  name: string;
  ok: boolean;
  detail: string;
  /** True when failing this loses something unrecoverable. */
  critical: boolean;
}

export async function health(): Promise<void> {
  const checks: Check[] = [];
  const client = new TechnocoreClient();
  const keypair = loadKeypair();
  const fp = fingerprint(keypair.did);

  // --- the notes that must not disappear ---------------------------------
  // "Never registered yet" and "registered, then reclaimed" look identical over
  // the wire and are completely different problems. Only the second is an
  // emergency, and an alert that fires constantly is an alert nobody reads.
  const didNote = await client.readNote(DID_NAMESPACE, fp).catch(() => null);
  const everClaimed = hasEverClaimed();
  checks.push({
    name: "DID note",
    ok: didNote !== null || !everClaimed,
    critical: everClaimed,
    detail: didNote
      ? "published"
      : everClaimed
        ? "RECLAIMED — we held this slot and lost it. The namespace is capped, so it is now contested again."
        : "not claimed yet — namespace at cap, claim job is waiting for a slot (expected)",
  });

  const contrib = await client.readNote(CONTRIB_NAMESPACE, fp).catch(() => null);
  checks.push({
    name: "contribution note",
    ok: contrib !== null,
    critical: true,
    detail: contrib
      ? "live — reclaimed only after 7 days with no write"
      : "GONE. If it was published before, it has been reclaimed",
  });

  // --- the jobs that keep those notes alive ------------------------------
  let launchd = "";
  try {
    launchd = execSync("launchctl list", { encoding: "utf8" });
  } catch {
    launchd = "";
  }
  for (const label of ["flop.keepalive", "flop.claim", "flop.autopilot"]) {
    const line = launchd.split("\n").find((l) => l.endsWith(label));
    const running = line !== undefined && !line.startsWith("-");
    checks.push({
      name: label,
      ok: running,
      critical: label === "flop.keepalive",
      detail: running
        ? `running (${line?.trim().split(/\s+/)[0]})`
        : line
          ? "installed but not running"
          : "not installed — run scripts/install-launchd.sh",
    });
  }

  // --- how close the local keepalive is to the cliff ----------------------
  const keepaliveLog = join(STATE_DIR, "flop.keepalive.log");
  if (existsSync(keepaliveLog)) {
    const ageHours = (Date.now() - statSync(keepaliveLog).mtimeMs) / 3_600_000;
    const budgetHours = LIMITS.retentionSeconds / 3600;
    checks.push({
      name: "last local refresh",
      ok: ageHours < budgetHours,
      critical: true,
      detail: `${ageHours.toFixed(1)}h ago (reclaim at ${budgetHours}h)`,
    });
  }

  // --- autopilot ----------------------------------------------------------
  checks.push({
    name: "autopilot kill switch",
    ok: !existsSync(join(STATE_DIR, "autopilot.off")),
    critical: false,
    detail: existsSync(join(STATE_DIR, "autopilot.off")) ? "ENGAGED — not replying" : "off (autopilot active)",
  });

  // --- key custody --------------------------------------------------------
  const keyFile = join(process.env.FLOP_HOME ?? join(import.meta.dir, "..", ".."), "keys", "agent.ed25519.pem");
  if (existsSync(keyFile)) {
    const mode = statSync(keyFile).mode & 0o777;
    checks.push({
      name: "key permissions",
      ok: (mode & 0o077) === 0,
      critical: true,
      detail: `${mode.toString(8)}${(mode & 0o077) === 0 ? "" : " — too permissive"}`,
    });
  }

  // --- report -------------------------------------------------------------
  const failures = checks.filter((c) => !c.ok);
  const criticalFailures = failures.filter((c) => c.critical);

  for (const c of checks) {
    const mark = c.ok ? " ok " : c.critical ? "CRIT" : "warn";
    console.log(`  [${mark}] ${c.name.padEnd(22)} ${c.detail}`);
  }

  console.log(
    `\n${checks.length - failures.length}/${checks.length} healthy` +
      (criticalFailures.length ? ` — ${criticalFailures.length} CRITICAL` : ""),
  );

  if (criticalFailures.length) {
    console.log("\nCritical means something unrecoverable is at risk:");
    for (const c of criticalFailures) console.log(`  - ${c.name}: ${c.detail}`);
    process.exitCode = 1;
  }
}
