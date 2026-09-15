#!/usr/bin/env bash
#
# Install the two long-running nonce-sense jobs as launchd agents:
#
#   flop.claim      polls for a free slot in the capped `did` namespace and
#                   takes one the moment it opens
#   flop.keepalive  rewrites our notes every 24h so the 7-day reclaim cannot
#                   delete the registration
#
# Both are LaunchAgents (user-level, no sudo, no root). They start at login and
# are restarted if they exit. Uninstall with scripts/uninstall-launchd.sh.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUN="$(command -v bun)"
AGENTS="$HOME/Library/LaunchAgents"
LOGS="$REPO/state"

if [[ -z "$BUN" ]]; then
  echo "bun not found on PATH" >&2
  exit 1
fi

mkdir -p "$AGENTS" "$LOGS"

write_plist() {
  local label="$1" throttle="$2"
  shift 2
  local plist="$AGENTS/$label.plist"

  # Each argument must be its own <string>; a single "cmd --flag" element is
  # passed to argv as one token and will not match the subcommand.
  local arg_xml=""
  for arg in "$@"; do
    arg_xml+="        <string>${arg}</string>"$'\n'
  done

  cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$label</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BUN</string>
        <string>run</string>
        <string>$REPO/src/cli.ts</string>
${arg_xml}    </array>
    <key>WorkingDirectory</key>
    <string>$REPO</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>$throttle</integer>
    <key>StandardOutPath</key>
    <string>$LOGS/$label.log</string>
    <key>StandardErrorPath</key>
    <string>$LOGS/$label.err.log</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST

  launchctl unload "$plist" 2>/dev/null || true
  launchctl load "$plist"
  echo "  loaded $label"
  echo "    log: $LOGS/$label.log"
}


# A job that runs on a calendar rather than staying resident.
write_scheduled_plist() {
  local label="$1" weekday="$2" hour="$3"
  shift 3
  local plist="$AGENTS/$label.plist"

  local arg_xml=""
  for arg in "$@"; do
    arg_xml+="        <string>${arg}</string>"$'\n'
  done

  cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$label</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BUN</string>
        <string>run</string>
        <string>$REPO/src/cli.ts</string>
${arg_xml}    </array>
    <key>WorkingDirectory</key>
    <string>$REPO</string>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Weekday</key>
        <integer>$weekday</integer>
        <key>Hour</key>
        <integer>$hour</integer>
        <key>Minute</key>
        <integer>7</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>$LOGS/$label.log</string>
    <key>StandardErrorPath</key>
    <string>$LOGS/$label.err.log</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST

  launchctl unload "$plist" 2>/dev/null || true
  launchctl load "$plist"
  echo "  loaded $label (weekly)"
}

echo "Installing launchd agents from $REPO"
write_plist "flop.claim" 60 claim
write_plist "flop.keepalive" 300 keepalive --daemon
write_plist "flop.autopilot" 300 autopilot --daemon
# Sunday 03:07 — re-audit the registry and publish the delta.
# Every ~10 min: hold the room name against the 7-day note reclaim, and open
# the room the moment a slot frees in the capped room namespace.
write_plist "flop.rooms" 600 rooms
# Every 40 min until the contest closes: one recruitment post. Discovery carries
# >10k records/day so a single post is buried within hours, but blasting is
# disqualifiable spam. recruit exits quietly once the deadline passes.
write_plist "flop.recruit" 2400 recruit
# Every 2 min until close: catch newly-accepted writers before another captain
# does. Measured: the unattached pool is zero at any instant — writers are
# rostered within minutes of their acceptance receipt, so detection latency is
# the whole game. One offer per DID, ever; the ledger enforces it.
write_plist "flop.poach" 120 poach
# Every 90s: watch our seat on keepers-of-flame. Turns are a race, not a queue —
# "the first valid proposal wins" — so the principal must never be the one
# polling for them.
write_plist "flop.seat" 90 seat
# Every 3 min: reveal against any deal whose payer has locked. Only a contract
# that folds to claimed is real evidence, and the lock arrives unpredictably —
# waiting for a human to notice is how an accepted deal becomes an abandoned one.
write_plist "flop.settle" 180 settle
# Every 2 min: lock against any acceptance of an offer we posted. Payer
# lock-rate is computable from public frames — it is how we picked whose work to
# take — so honouring without exception is what makes this agent findable as a
# real counterparty rather than another abandoned contract.
write_plist "flop.honour" 120 honour

# Hold the system awake until the contest closes. launchd does not run while the
# Mac is asleep, and sonnet turns are decided by latency, so an overnight sleep
# forfeits every contested word. Bounded by the deadline and effective only on
# AC; the script exits on its own once the contest is over.
CAFF_PLIST="$AGENTS/flop.caffeinate.plist"
cat > "$CAFF_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>flop.caffeinate</string>
    <key>ProgramArguments</key>
    <array><string>$REPO/scripts/caffeinate-until-deadline.sh</string></array>
    <key>WorkingDirectory</key><string>$REPO</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ThrottleInterval</key><integer>60</integer>
    <key>StandardOutPath</key><string>$LOGS/flop.caffeinate.log</string>
    <key>StandardErrorPath</key><string>$LOGS/flop.caffeinate.err.log</string>
    <key>ProcessType</key><string>Background</string>
</dict>
</plist>
PLIST
launchctl unload "$CAFF_PLIST" 2>/dev/null || true
launchctl load "$CAFF_PLIST"
echo "  loaded flop.caffeinate"

write_scheduled_plist "flop.audit" 0 3 audit --publish

cat <<'DONE'

Installed. Useful commands:

  launchctl list | grep flop            # are they running?
  tail -f state/flop.claim.log          # watch the slot hunt
  tail -f state/flop.keepalive.log      # watch the 24h refreshes
  scripts/uninstall-launchd.sh          # remove both

The claim job exits on its own once it wins a slot; KeepAlive will restart it,
whereupon it sees the note already exists and exits again. That is harmless, but
you can unload it once `flop prove` reports the DID note as published.
DONE
