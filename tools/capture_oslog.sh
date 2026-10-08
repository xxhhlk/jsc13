#!/bin/sh
# capture_oslog.sh - capture jsc13's log from the unified log.
#
# The WebContent sandbox denies writes to /var/tmp, so jsc13 cannot keep a file
# log; it emits NSLog, which lands in the unified log. This script streams that
# log, forces a fresh WebContent process so the tweak re-initialises, and prints
# the jsc13 lines.
#
# Run as root on the device. The WebContent kill below is harmless: WebKit
# respawns it on demand.

OUT=/var/tmp/jsc13_oslog.txt
PATTERN=${1:-jsc13}

rm -f "$OUT"

# Start streaming the unified log.
oslog > "$OUT" 2>&1 &
OSL=$!
sleep 1

# Force new WebContent processes so the tweak runs its constructor again.
for pid in $(ps aux 2>/dev/null | grep WebContent | grep -v grep | awk '{print $2}'); do
    kill -9 "$pid" 2>/dev/null
done

sleep 5
kill "$OSL" 2>/dev/null

echo "=== $PATTERN lines ==="
grep -a "$PATTERN" "$OUT" 2>/dev/null || echo "(none)"
