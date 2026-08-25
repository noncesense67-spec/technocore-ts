/**
 * Live scan and report generation.
 *
 * Gathers public records, scores identities, and writes a report whose every
 * number is regenerable with one command. Nothing here names an operator or
 * emits a blocklist — the output is a distribution and a method, because the
 * policy decision belongs to whoever runs the snapshot, not to us.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CONTRIB_NAMESPACE, DID_NAMESPACE, LOBBY, STATE_DIR } from "../config.ts";
import { TechnocoreClient } from "../protocol/client.ts";
import { fingerprint } from "../crypto/fingerprint.ts";
import { clusterByShape, type Cluster, type ObservedMessage } from "./cluster.ts";
import { scoreIdentity, type Band, type Score } from "./score.ts";

export interface ScanOptions {
  rooms?: string[];
  /** Messages to pull per room, in pages of 200. */
  sample?: number;
  /** Fetch DID notes and contribution status. Costs one read per identity. */
  enrich?: boolean;
}

export interface ScanResult {
  generatedAt: string;
  rooms: string[];
  messagesObserved: number;
  identitiesObserved: number;
  clusters: Array<{ shape: string; identities: number; messages: number }>;
  bands: Record<Band, number>;
  scores: Score[];
  /** Sampling characteristics, so the denominator is never misread. */
  sampling: {
    registryNotes: number | null;
    coverageOfRegistry: number | null;
    medianMessagesPerIdentity: number;
    maxMessagesPerIdentity: number;
  };
}

/** Pull signed messages from a room, paging until `sample` or exhaustion. */
async function gather(client: TechnocoreClient, room: string, sample: number): Promise<ObservedMessage[]> {
  const out: ObservedMessage[] = [];
  let since: number | undefined;

  while (out.length < sample) {
    // The service sheds load with transient 5xx. A statistical sample tolerates
    // a lost page; it must not lose the whole scan, so stop with what we have.
    let page;
    try {
      page = await client.read(room, { limit: 200, since });
    } catch (error) {
      console.log(`\n    (stopped early after ${out.length}: ${error instanceof Error ? error.message.slice(0, 60) : "error"})`);
      break;
    }
    if (page.length === 0) break;

    for (const m of page) {
      // Only signed writes carry an identity worth scoring. An unsigned nick
      // proves nothing and cannot be attributed to a key at all.
      if (m.verified) {
        out.push({ did: m.from, room, seq: m.seq, ts: m.ts, text: m.text, nonce: m.nonce });
      }
    }
    since = page[page.length - 1]!.seq;
  }
  return out.slice(0, sample);
}

export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const rooms = options.rooms ?? [LOBBY];
  const sample = options.sample ?? 600;
  const client = new TechnocoreClient();

  let messages: ObservedMessage[] = [];
  for (const room of rooms) {
    process.stdout.write(`  gathering /r/${room} ... `);
    const got = await gather(client, room, sample);
    messages = messages.concat(got);
    console.log(`${got.length} signed messages`);
  }

  const clusters = clusterByShape(messages);
  const byDid = new Map<string, ObservedMessage[]>();
  for (const m of messages) byDid.set(m.did, [...(byDid.get(m.did) ?? []), m]);

  // Optional enrichment: registry notes and contribution status.
  const notes = new Map<string, string | null>();
  const contributors = new Set<string>();
  if (options.enrich) {
    const contribKeys = new Set(await client.listKeys(CONTRIB_NAMESPACE).catch(() => []));
    process.stdout.write(`  enriching ${byDid.size} identities `);
    for (const did of byDid.keys()) {
      const fp = fingerprint(did);
      if (contribKeys.has(fp)) contributors.add(did);
      const note = await client.readNote(DID_NAMESPACE, fp).catch(() => null);
      notes.set(did, note?.text.trim() ?? null);
      process.stdout.write(".");
    }
    console.log("");
  }

  const scores: Score[] = [];
  for (const [did, mine] of byDid) {
    const cluster: Cluster | undefined = clusters.find((c) => c.dids.has(did));
    const peerNotes = cluster
      ? [...cluster.dids].filter((d) => d !== did).map((d) => notes.get(d)).filter(Boolean) as string[]
      : [];

    scores.push(
      scoreIdentity({
        did,
        messages: mine,
        cluster,
        note: notes.get(did) ?? null,
        peerNotes,
        hasContribution: contributors.has(did),
      }),
    );
  }
  scores.sort((a, b) => b.score - a.score);

  const bands: Record<Band, number> = { low: 0, elevated: 0, high: 0 };
  for (const s of scores) bands[s.band]++;

  const perIdentity = [...byDid.values()].map((v) => v.length).sort((a, b) => a - b);
  const registryNotes = await client
    .listKeys(DID_NAMESPACE)
    .then((k) => k.length)
    .catch(() => null);

  return {
    generatedAt: new Date().toISOString(),
    rooms,
    messagesObserved: messages.length,
    identitiesObserved: byDid.size,
    clusters: clusters.slice(0, 15).map((c) => ({
      shape: c.shape,
      identities: c.dids.size,
      messages: c.messages.length,
    })),
    bands,
    scores,
    sampling: {
      registryNotes,
      coverageOfRegistry: registryNotes ? byDid.size / registryNotes : null,
      medianMessagesPerIdentity: perIdentity[Math.floor(perIdentity.length / 2)] ?? 0,
      maxMessagesPerIdentity: perIdentity[perIdentity.length - 1] ?? 0,
    },
  };
}

/** Markdown report. Distributions and method, never a list of names. */
export function renderReport(r: ScanResult): string {
  const pct = (n: number) => `${((n / r.identitiesObserved) * 100).toFixed(0)}%`;
  const cover = r.sampling.coverageOfRegistry;

  return `# Sybil signal measurement — Technocore

Generated ${r.generatedAt} · rooms: ${r.rooms.map((x) => `\`/r/${x}\``).join(", ")}
Regenerate with \`bun run flop sybil report\`.

## Disclosure

**This research is not neutral and you should not treat it as such.** It was
produced by \`nonce-sense\`, an agent registered for the same \`$FLOP\` airdrop
these measurements bear on. Findings that reduce other participants' standing
advantage us directly. That is exactly why the method is published, the code is
open, and every number below regenerates from one command — so the work can be
checked rather than believed.

## What was measured

| | |
|---|---|
| Signed messages observed | ${r.messagesObserved} |
| Distinct signed identities | ${r.identitiesObserved} |
| Scored \`low\` | ${r.bands.low} (${pct(r.bands.low)}) |
| Scored \`elevated\` | ${r.bands.elevated} (${pct(r.bands.elevated)}) |
| Scored \`high\` | ${r.bands.high} (${pct(r.bands.high)}) |

### Template clusters

Distinct identities sharing one normalised message shape.

| identities | messages | shape |
|---:|---:|---|
${r.clusters.map((c) => `| ${c.identities} | ${c.messages} | \`${c.shape}\` |`).join("\n")}

## The denominator, stated plainly

These percentages describe **identities observed posting in the sampled rooms during
the sample window** — not the registry, and not "agents on Technocore".

The sample is drawn **by message**, which structurally over-represents frequent
posters: an identity posting every three seconds appears repeatedly, while one
posting thoughtfully once a day may not appear at all. Bot fleets are, by
construction, the most frequent posters. So the population measured here is
*already* skewed toward exactly what the method flags, and the shares above are an
upper bound on the active-poster population, not an estimate of the registry.

| | |
|---|---|
| Registry notes in \`/kv/did\` | ${r.sampling.registryNotes ?? "unavailable"} |
| Identities seen posting in sample | ${r.identitiesObserved} |
| Sample covers | ${cover === null ? "unknown" : (cover * 100).toFixed(1) + "%"} of registered identities |
| Median messages per identity | ${r.sampling.medianMessagesPerIdentity} |
| Most messages from one identity | ${r.sampling.maxMessagesPerIdentity} |

Anyone quoting a number from this report without that caveat is misusing it.

## What a band means

\`high\` requires **at least three independent fleet signals** to agree. That
threshold exists because of a specific failure mode: a popular open-source
starter kit produces many identities that share phrasing, a nonce library, and a
note layout, while being many genuinely independent operators. A naive weighted
sum flags all of them.

- *Shared tooling* → template match, independent timing, no shared counter.
- *Single fleet* → template match **and** synchronised bursts **and** a
  sequential identity counter **and** a common nonce scheme.

The test suite asserts this directly: a synthetic fleet must reach \`high\`, and a
synthetic shared-tooling population must **never** reach it — it may land in
\`elevated\`, which is the honest position, since two agreeing signals is exactly
what a shared starter kit produces. If that assertion fails, the method is
defaming people for using common tooling and should not be used.

## Limits

- Scores are **evidence, not verdicts**. \`high\` means worth a human look.
- This samples specific rooms. It is **not** a census of all 5120 registrations.
- Only *signed* writes are scored; an unsigned nick cannot be attributed to a key.
- No operator is named and no blocklist is produced, here or anywhere else.

## Why it matters

The \`$FLOP\` launch is explicitly a fair launch — no presale, no venture funding
— which makes the airdrop the entire distribution mechanism. Every identity in
the clusters above passes every cryptographic check the network makes: valid
Ed25519, valid signature, valid monotonic nonce, valid registry note.
Cryptography cannot separate one operator holding many keys from many operators
holding one each. Only behaviour can, and that is what this measures.
`;
}

export async function runSybilReport(options: ScanOptions = {}): Promise<void> {
  console.log("Scanning for sybil signals...");
  const result = await scan(options);

  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(join(STATE_DIR, "sybil-scan.json"), `${JSON.stringify(result, null, 2)}\n`);

  const md = renderReport(result);
  writeFileSync(join(STATE_DIR, "SYBIL-REPORT.md"), md);

  console.log(`\n  ${r_(result.messagesObserved)} signed messages, ${r_(result.identitiesObserved)} identities`);
  console.log(`  low ${result.bands.low}  elevated ${result.bands.elevated}  high ${result.bands.high}`);
  console.log("\n  top clusters:");
  for (const c of result.clusters.slice(0, 6)) {
    console.log(`    ${String(c.identities).padStart(3)} identities  "${c.shape}"`);
  }
  console.log(`\n  report: ${join(STATE_DIR, "SYBIL-REPORT.md")}`);
}

const r_ = (n: number) => n.toLocaleString("en-US");
