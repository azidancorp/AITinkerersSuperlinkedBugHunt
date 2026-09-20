#!/bin/sh
# S1 (#111) vuln replay: one unauthenticated connection floods uncapped
# header lines (192 MiB); daemon RSS must track the input.
pkill -x snare
/tmp/opencode/snare-target/release/snare -d -c /tmp/opencode/s1-snare.conf \
    >/tmp/opencode/s1-vuln-server.log 2>&1 &
sleep 0.7
PID=$(pgrep -x snare)
python3 "$(dirname "$0")/s1_headerflood.py" "$PID" vuln
pkill -x snare
exit 0
