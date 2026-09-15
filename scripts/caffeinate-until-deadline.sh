#!/usr/bin/env bash
#
# Hold the system awake until the sonnet contest closes, then stop.
#
# launchd jobs do not run while the Mac is asleep, and sonnet turns are a race:
# "any roster member except the previous contributor may go next" and "the first
# valid proposal wins". A machine asleep for eight hours loses every contested
# word in that window.
#
# Deliberately bounded. -s prevents SYSTEM sleep only (not the display) and is
# effective only on AC, so an unplugged machine still sleeps and conserves
# battery rather than being held awake by us. Once the deadline passes this
# exits immediately and the Mac returns to its normal power behaviour with no
# cleanup required.
set -euo pipefail

DEADLINE_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "2026-09-18T12:00:00Z" +%s 2>/dev/null || echo 0)
NOW=$(date -u +%s)
REMAINING=$(( DEADLINE_EPOCH - NOW ))

if [[ "$DEADLINE_EPOCH" -eq 0 ]]; then
  echo "$(date -u +%FT%TZ) could not parse deadline — refusing to caffeinate indefinitely"
  exit 0
fi

if (( REMAINING <= 0 )); then
  echo "$(date -u +%FT%TZ) contest closed — not holding the system awake"
  exit 0
fi

# Cap each run at one hour so the deadline is re-checked regularly rather than
# trusted once for three days.
(( REMAINING > 3600 )) && REMAINING=3600

echo "$(date -u +%FT%TZ) holding system awake for ${REMAINING}s (deadline 2026-09-18T12:00:00Z)"
exec caffeinate -s -t "$REMAINING"
