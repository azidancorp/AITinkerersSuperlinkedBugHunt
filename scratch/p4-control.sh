#!/bin/sh
# P4 (#128) control replay: inert baseline — the same others-class attack
# oracle against a path with no socket and no pizauth layout at all.
# If no vulnerability exists, this is indistinguishable from the vuln run.
rm -rf /tmp/opencode/p4-v-ctl
python3 "$(dirname "$0")/p4_connect.py" /tmp/opencode/p4-v-ctl/pizauth/pizauth.sock
exit 0
