#!/bin/sh
# Independent second-opinion vuln replay for ledger #111 (snare S1):
# ONE unauthenticated connection floods non-terminating header lines
# (192 MiB); daemon VmRSS must track the input. Binary built from the
# read-only pinned-HEAD source into scratch/target-snare (offline).
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN=/home/azidan/AQL/AI/AITinkerers/scratch/target-snare/release/snare
mkdir -p "$DIR/evidence"
"$BIN" -d -c "$DIR/snare.conf" >"$DIR/evidence/server-vuln.log" 2>&1 &
PID=$!
python3 "$DIR/measure.py" "$PID" vuln
RC=$?
kill "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
exit "$RC"
