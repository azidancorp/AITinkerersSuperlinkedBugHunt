#!/bin/bash
# V6 vuln replay (ledger #134). UNRUN at 2026-09-20 — see worksheet.md.
# Attacker confirms a pending upload that belongs to a VICTIM project, then
# commits it to the attacker's own issue and lists attachments.
# Boundary crossed iff the foreign blob becomes listable/downloadable under
# the attacker's project.
set -u
BASE=http://127.0.0.1:8081
ATK_TOKEN="${ATK_TOKEN:?}"
FOREIGN_UPLOAD="${FOREIGN_UPLOAD:?seeded victim pending-upload UUID required}"
ATK_PROJECT="${ATK_PROJECT:?}"
ATK_ISSUE="${ATK_ISSUE:?}"

resp=$(curl -s -X POST "$BASE/v1/attachments/confirm" \
  -H "Authorization: Bearer $ATK_TOKEN" -H 'content-type: application/json' \
  -d "{\"project_id\":\"$ATK_PROJECT\",\"upload_id\":\"$FOREIGN_UPLOAD\",\"issue_id\":\"$ATK_ISSUE\",\"hash\":\"canaryhash\",\"filename\":\"canary.txt\",\"content_type\":\"text/plain\",\"size_bytes\":10}")
echo "confirm response: $resp"
att_id=$(printf '%s' "$resp" | sed -n 's/.*"id":"\([0-9a-f-]*\)".*/\1/p' | head -1)
if [ -n "$att_id" ]; then
  curl -s -o /dev/null -X POST "$BASE/v1/issues/$ATK_ISSUE/attachments/commit" \
    -H "Authorization: Bearer $ATK_TOKEN" -H 'content-type: application/json' \
    -d "{\"attachment_ids\":[\"$att_id\"]}"
  listed=$(curl -s -H "Authorization: Bearer $ATK_TOKEN" "$BASE/v1/issues/$ATK_ISSUE/attachments")
  echo "attacker listing: $listed"
  case "$listed" in
    *canary.txt*) echo "CANARY-COMPROMISED: foreign staged file attached and listed under attacker project"; exit 1;;
  esac
fi
echo "CLEAN: foreign upload confirmation rejected"
exit 0
