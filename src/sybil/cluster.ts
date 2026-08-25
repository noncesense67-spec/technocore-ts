/**
 * Template clustering.
 *
 * Normalises message text so that scripted variants collapse onto one shape:
 * "FLOP agent 74 check-in" and "FLOP agent 212 check-in" become the same key.
 *
 * Clustering on its own proves nothing about who is behind an identity. Two
 * hundred people running the same open-source starter kit produce one cluster
 * and are still two hundred independent operators. This module only groups; the
 * question of what a group *means* is deliberately left to score.ts, which
 * requires several independent signals to agree before it says anything.
 */

export interface ObservedMessage {
  did: string;
  room: string;
  seq: number;
  /** ISO 8601, as served by the protocol. */
  ts: string;
  text: string;
  nonce?: string;
}

/** Strip the parts a script varies, keep the parts a script repeats. */
export function normalise(text: string): string {
  return text
    .toLowerCase()
    .replace(/did:key:z[a-z0-9]+/gi, "@did")
    .replace(/https?:\/\/\S+/g, "@url")
    .replace(/\b[0-9a-f]{16,}\b/gi, "@hex")
    .replace(/\d+/g, "#")
    .replace(/[^a-z@# ]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/** The clustering key: the opening of a normalised message. */
export function shapeKey(text: string, words = 5): string {
  return normalise(text).split(" ").slice(0, words).join(" ");
}

export interface Cluster {
  shape: string;
  dids: Set<string>;
  messages: ObservedMessage[];
}

/** Group messages by normalised shape. Clusters of one are dropped. */
export function clusterByShape(messages: ObservedMessage[], words = 5): Cluster[] {
  const byShape = new Map<string, Cluster>();

  for (const m of messages) {
    const shape = shapeKey(m.text, words);
    // Very short shapes carry no signal — "ok", "hi", "yes" are not templates.
    if (!shape || shape.split(" ").length < 3) continue;

    const existing = byShape.get(shape);
    if (existing) {
      existing.dids.add(m.did);
      existing.messages.push(m);
    } else {
      byShape.set(shape, { shape, dids: new Set([m.did]), messages: [m] });
    }
  }

  return [...byShape.values()]
    .filter((c) => c.dids.size > 1)
    .sort((a, b) => b.dids.size - a.dids.size);
}

/** Every identity that shares a template with at least `min` other identities. */
export function clusteredIdentities(clusters: Cluster[], min = 3): Set<string> {
  const dids = new Set<string>();
  for (const c of clusters) {
    if (c.dids.size >= min) for (const d of c.dids) dids.add(d);
  }
  return dids;
}
