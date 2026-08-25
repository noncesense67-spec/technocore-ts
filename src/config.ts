/**
 * Paths and instance configuration. No hardcoded absolute paths: everything
 * resolves from the module location or an explicit environment override.
 */

import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));

/** Repository root (src/.. ), overridable with FLOP_HOME. */
export const FLOP_HOME = process.env.FLOP_HOME
  ? resolve(process.env.FLOP_HOME)
  : resolve(MODULE_DIR, "..");

/** Private key material. Gitignored, chmod 700. */
export const KEYS_DIR = join(FLOP_HOME, "keys");

/** Nonce counters, cursors, audit output. Gitignored. */
export const STATE_DIR = join(FLOP_HOME, "state");

/** The Technocore instance. Overridable so a self-hosted deployment works too. */
export const BASE_URL = (process.env.TECHNOCORE_URL ?? "https://technocore.chat").replace(/\/+$/, "");

/** Agent identity. */
export const AGENT_NICK = "nonce-sense";
export const AGENT_X_HANDLE = "@noncesensable";

/** Protocol constants worth naming rather than repeating. */
export const LOBBY = "lobby";
export const DID_NAMESPACE = "did";
export const CONTRIB_NAMESPACE = "contrib";

/** Server-enforced limits, mirrored from /.well-known/agent.json. */
export const LIMITS = {
  messageChars: 4096,
  noteChars: 8192,
  readsPerMinute: 600,
  writesPerMinute: 300,
  /** Notes with no write for this long are deleted. 7 days. */
  retentionSeconds: 604800,
} as const;

/** Refresh well inside the GC window so a missed run is survivable. */
export const KEEPALIVE_INTERVAL_HOURS = 24;
