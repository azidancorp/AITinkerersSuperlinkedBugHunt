#!/bin/sh
# S2 (#112) control replay: same server, same legitimate delivery, no attackers.
# Expected: HTTP/1.1 200 OK, CLAIM_EFFECT=none.
pkill -x snare
/tmp/opencode/snare-target/release/snare -d -c /tmp/opencode/s2-snare.conf \
    >/tmp/opencode/s2-ctl-server.log 2>&1 &
sleep 0.7
python3 "$(dirname "$0")/s2_legit.py" 18011 6
pkill -x snare
exit 0
