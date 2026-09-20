#!/bin/sh
# P4 (#128) vuln replay: recreate pizauth's exact control-socket layout
# (cache_path() 0700 enforcement + plain UnixListener::bind, server/mod.rs:444)
# under the claimed worst-case umask 000, then run the others-class attack
# oracle against the live socket. Claimed effect: unauthorized cross-UID
# access. Expected at HEAD: CLAIM_EFFECT=none (0700 parents block search).
pkill -x p4_server
rm -rf /tmp/opencode/p4-v
(
    umask 000
    XDG_RUNTIME_DIR=/tmp/opencode/p4-v
    export XDG_RUNTIME_DIR
    exec /tmp/opencode/p4_server pizauth
) >/tmp/opencode/p4-v.log 2>&1 &
i=0
while [ $i -lt 30 ]; do
    [ -S /tmp/opencode/p4-v/pizauth/pizauth.sock ] && break
    sleep 0.1
    i=$((i + 1))
done
python3 "$(dirname "$0")/p4_connect.py" /tmp/opencode/p4-v/pizauth/pizauth.sock
pkill -x p4_server
exit 0
