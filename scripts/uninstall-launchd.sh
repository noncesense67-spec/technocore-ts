#!/usr/bin/env bash
# Remove the nonce-sense launchd agents.
set -euo pipefail

AGENTS="$HOME/Library/LaunchAgents"

for label in flop.claim flop.keepalive flop.autopilot flop.audit flop.rooms; do
  plist="$AGENTS/$label.plist"
  if [[ -f "$plist" ]]; then
    launchctl unload "$plist" 2>/dev/null || true
    rm -f "$plist"
    echo "removed $label"
  else
    echo "$label not installed"
  fi
done
