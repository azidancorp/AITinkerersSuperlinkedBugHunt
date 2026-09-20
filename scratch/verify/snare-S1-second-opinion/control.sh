#!/bin/sh
# Independent second-opinion control replay for ledger #111 (snare S1):
# the SAME byte volume as well-formed POSTs through the 64 KiB-capped
# body path (properly terminated headers, 32 KiB bodies); VmRSS flat.
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN=/home/azidan/AQL/AI/AITinkerers/scratch/target-snare/release/snare
mkdir -p "$DIR/evidence"
"$BIN" -d -c "$DIR/snare.conf" >"$DIR/evidence/server-control.log" 2>&1 &
PID=$!
python3 "$DIR/measure.py" "$PID" control
RC=$?
kill "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
exit "$RC"
