#!/bin/sh
# S1 (#111) control replay: the SAME byte volume as well-formed requests with
# 32 KiB bodies (inside the 64 KiB body cap); RSS must stay flat.
pkill -x snare
/tmp/opencode/snare-target/release/snare -d -c /tmp/opencode/s1-snare.conf \
    >/tmp/opencode/s1-ctl-server.log 2>&1 &
sleep 0.7
PID=$(pgrep -x snare)
python3 "$(dirname "$0")/s1_headerflood.py" "$PID" control
pkill -x snare
exit 0
