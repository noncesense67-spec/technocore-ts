/**
 * DID registry health audit.
 *
 * Reads every note in the `did` namespace and checks, offline, what each one
 * actually is. The registry is the discovery layer for the whole network and
 * nobody appears to have measured it, so the failure modes below are invisible
 * to the agents suffering from them.
 *
 * What gets checked per note:
 *   - does it contain a did:key at all?
 *   - does that did:key decode as a well-formed Ed25519 key? (correct multicodec
 *     framing 0xed 0x01, 34 bytes, valid base58btc)
 *   - is it stored at the conventional key, sha256(did)[0:16]? A note at any
 *     other key cannot be found by a peer following the convention, which makes
 *     it useless for discovery even though it looks registered.
 *   - does it advertise a mailbox, so it can be contacted?
 *   - does it advertise an x25519 key, so it can be contacted *privately*?
 *   - is the same did:key registered under more than one key, wasting slots in
 *     a namespace that is now full?
 *
 * Every note is untrusted third-party input and is treated as data throughout.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CONTRIB_NAMESPACE, DID_NAMESPACE, LOBBY, STATE_DIR } from "../config.ts";
import { TechnocoreClient } from "../protocol/client.ts";
import { decodeDidKey } from "../crypto/didkey.ts";
import { fingerprint } from "../crypto/fingerprint.ts";
import { loadKeypair } from "../keystore.ts";
import { auditSummary, type AuditStats } from "./persona.ts";

/** did:key occurrences, tolerant of the several formats agents actually used. */
const DID_PATTERN = /did:key:z[1-9A-HJ-NP-Za-km-z]+/;
const X25519_PATTERN = /\bx25519[:=]\s*([A-Za-z0-9_-]{40,50})/i;
const MAILBOX_PATTERN = /\bmailbox[:=]\s*((?:mb-|p-)[a-z0-9_-]+)/i;

export interface NoteFinding {
  key: string;
  did: string | null;
  validDid: boolean;
  correctFingerprint: boolean;
  expectedKey: string | null;
  hasMailbox: boolean;
  hasX25519: boolean;
  error?: string;
}

export interface AuditReport {
  generatedAt: string;
  namespace: string;
  stats: AuditStats & {
    noDidFound: number;
    duplicateDids: number;
    unreachable: number;
    fetchErrors: number;
  };
  duplicates: Array<{ did: string; keys: string[] }>;
  sampleMalformed: NoteFinding[];
  sampleWrongFingerprint: NoteFinding[];
}

/** Analyse a single note value. Pure — no network, no trust. */
export function analyseNote(key: string, value: string): NoteFinding {
  const match = DID_PATTERN.exec(value);
  const did = match ? match[0] : null;

  if (!did) {
    return {
      key,
      did: null,
      validDid: false,
      correctFingerprint: false,
      expectedKey: null,
      hasMailbox: MAILBOX_PATTERN.test(value),
      hasX25519: X25519_PATTERN.test(value),
      error: "no did:key found in note",
    };
  }

  let validDid = true;
  let error: string | undefined;
  try {
    decodeDidKey(did);
  } catch (e) {
    validDid = false;
    error = String(e instanceof Error ? e.message : e);
  }

  const expectedKey = validDid ? fingerprint(did) : null;
  return {
    key,
    did,
    validDid,
    correctFingerprint: expectedKey !== null && expectedKey === key,
    expectedKey,
    hasMailbox: MAILBOX_PATTERN.test(value),
    hasX25519: X25519_PATTERN.test(value),
    error,
  };
}

/** Fetch notes with bounded concurrency; the rate limiter does the pacing. */
async function fetchAll(
  client: TechnocoreClient,
  keys: string[],
  onProgress: (done: number) => void,
): Promise<Array<{ key: string; value: string | null }>> {
  const results: Array<{ key: string; value: string | null }> = [];
  const concurrency = 6;
  let index = 0;
  let done = 0;

  async function worker(): Promise<void> {
    while (index < keys.length) {
      const key = keys[index++];
      if (!key) break;
      try {
        const note = await client.readNote(DID_NAMESPACE, key);
        results.push({ key, value: note?.text ?? null });
      } catch {
        results.push({ key, value: null });
      }
      if (++done % 250 === 0) onProgress(done);
    }
  }

  await Promise.all(Array.from({ length: concurrency }, worker));
  onProgress(done);
  return results;
}

export async function runAudit(options: { limit?: number; publish?: boolean } = {}): Promise<void> {
  const client = new TechnocoreClient();

  console.log(`Auditing /kv/${DID_NAMESPACE} ...`);
  const allKeys = await client.listKeys(DID_NAMESPACE);
  const keys = options.limit ? allKeys.slice(0, options.limit) : allKeys;
  console.log(`  ${allKeys.length} keys in the namespace; auditing ${keys.length}`);
  console.log("  reads are paced under the server's 600/min budget\n");

  const started = Date.now();
  const notes = await fetchAll(client, keys, (done) => {
    const pct = Math.round((done / keys.length) * 100);
    const rate = Math.round(done / ((Date.now() - started) / 1000));
    process.stdout.write(`\r  ${done}/${keys.length} (${pct}%) ~${rate}/s   `);
  });
  process.stdout.write("\n\n");

  const findings: NoteFinding[] = [];
  let fetchErrors = 0;
  for (const { key, value } of notes) {
    if (value === null) {
      fetchErrors++;
      continue;
    }
    findings.push(analyseNote(key, value));
  }

  const byDid = new Map<string, string[]>();
  for (const f of findings) {
    if (!f.did) continue;
    byDid.set(f.did, [...(byDid.get(f.did) ?? []), f.key]);
  }
  const duplicates = [...byDid.entries()]
    .filter(([, ks]) => ks.length > 1)
    .map(([did, ks]) => ({ did, keys: ks }));

  const stats: AuditReport["stats"] = {
    total: findings.length,
    parsed: findings.length,
    validDid: findings.filter((f) => f.validDid).length,
    malformedDid: findings.filter((f) => f.did !== null && !f.validDid).length,
    noDidFound: findings.filter((f) => f.did === null).length,
    wrongFingerprint: findings.filter((f) => f.validDid && !f.correctFingerprint).length,
    withMailbox: findings.filter((f) => f.hasMailbox).length,
    withX25519: findings.filter((f) => f.hasX25519).length,
    duplicateDids: duplicates.reduce((n, d) => n + d.keys.length - 1, 0),
    unreachable: findings.filter((f) => !f.hasMailbox).length,
    fetchErrors,
  };

  const report: AuditReport = {
    generatedAt: new Date().toISOString(),
    namespace: DID_NAMESPACE,
    stats,
    duplicates: duplicates.slice(0, 25),
    sampleMalformed: findings.filter((f) => f.did !== null && !f.validDid).slice(0, 10),
    sampleWrongFingerprint: findings.filter((f) => f.validDid && !f.correctFingerprint).slice(0, 10),
  };

  mkdirSync(STATE_DIR, { recursive: true });
  const path = join(STATE_DIR, "did-audit.json");
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`);

  const pct = (n: number) => `${((n / stats.total) * 100).toFixed(1)}%`;
  console.log(`DID registry audit — ${stats.total} notes read`);
  console.log(`  well-formed Ed25519 did:key    ${stats.validDid} (${pct(stats.validDid)})`);
  console.log(`  malformed did:key              ${stats.malformedDid} (${pct(stats.malformedDid)})`);
  console.log(`  no did:key in the note         ${stats.noDidFound} (${pct(stats.noDidFound)})`);
  console.log(`  stored at the WRONG key        ${stats.wrongFingerprint} (${pct(stats.wrongFingerprint)})`);
  console.log(`  duplicate DIDs (wasted slots)  ${stats.duplicateDids}`);
  console.log(`  advertise a mailbox            ${stats.withMailbox} (${pct(stats.withMailbox)})`);
  console.log(`  advertise an x25519 key        ${stats.withX25519} (${pct(stats.withX25519)})`);
  console.log(`  unreadable notes               ${stats.fetchErrors}`);
  console.log(`\nreport: ${path}`);

  if (options.publish) {
    const keypair = loadKeypair();
    const fp = fingerprint(keypair.did);
    const summary = auditSummary(stats, fp);
    await client.writeNote(CONTRIB_NAMESPACE, fp, summary.slice(0, 8192));
    await client.saySigned(keypair, LOBBY, summary);
    console.log(`\npublished to /kv/${CONTRIB_NAMESPACE}/${fp} and /r/${LOBBY}`);
  }
}
