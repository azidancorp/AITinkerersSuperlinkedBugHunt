#!/bin/bash
# V5 vuln replay (ledger #133). UNRUN at 2026-09-20 — requires the seeded
# harness server described in worksheet.md. Wrapped by remote-probe.sh.
# Attacker (org A, project PA) creates a workspace supplying a victim issue
# UUID from org B. Boundary crossed iff org B's issue was mutated.
set -u
BASE=http://127.0.0.1:8081
ATK_TOKEN="${ATK_TOKEN:?seeded attacker JWT required}"
VICTIM_ISSUE="${VICTIM_ISSUE:?seeded org-B issue UUID required}"
ATK_PROJECT="${ATK_PROJECT:?seeded org-A project UUID required}"

before=$(curl -s -H "Authorization: Bearer $ATK_TOKEN" "$BASE/v1/issues/$VICTIM_ISSUE" || true)
curl -s -o /dev/null -X POST "$BASE/v1/workspaces" \
  -H "Authorization: Bearer $ATK_TOKEN" -H 'content-type: application/json' \
  -d "{\"project_id\":\"$ATK_PROJECT\",\"local_workspace_id\":\"canary-ws-1\",\"issue_id\":\"$VICTIM_ISSUE\",\"name\":\"canary\",\"archived\":false,\"files_changed\":0,\"lines_added\":0,\"lines_removed\":0}"
after=$(curl -s -H "Authorization: Bearer $ATK_TOKEN" "$BASE/v1/issues/$VICTIM_ISSUE" || true)

echo "victim issue before: $before"
echo "victim issue after:  $after"
if [ "$before" != "$after" ]; then
  echo "CANARY-COMPROMISED: foreign org issue mutated via unchecked issue_id"
  exit 1
fi
echo "CLEAN: foreign issue unchanged"
exit 0
