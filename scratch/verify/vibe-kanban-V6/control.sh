#!/bin/bash
# V6 control replay (ledger #134): identical to vuln.sh minus the trigger —
# the pending upload belongs to the ATTACKER's own project (legitimate flow).
set -u
BASE=http://127.0.0.1:8081
ATK_TOKEN="${ATK_TOKEN:?}"
OWN_UPLOAD="${OWN_UPLOAD:?seeded attacker pending-upload UUID required}"
ATK_PROJECT="${ATK_PROJECT:?}"
ATK_ISSUE="${ATK_ISSUE:?}"

resp=$(curl -s -X POST "$BASE/v1/attachments/confirm" \
  -H "Authorization: Bearer $ATK_TOKEN" -H 'content-type: application/json' \
  -d "{\"project_id\":\"$ATK_PROJECT\",\"upload_id\":\"$OWN_UPLOAD\",\"issue_id\":\"$ATK_ISSUE\",\"hash\":\"canaryhash\",\"filename\":\"canary.txt\",\"content_type\":\"text/plain\",\"size_bytes\":10}")
att_id=$(printf '%s' "$resp" | sed -n 's/.*"id":"\([0-9a-f-]*\)".*/\1/p' | head -1)
if [ -n "$att_id" ]; then
  echo "CLEAN: own-upload confirm succeeded (intended behaviour)"
  exit 0
fi
echo "UNEXPECTED: legitimate own-upload confirm rejected"
exit 0
