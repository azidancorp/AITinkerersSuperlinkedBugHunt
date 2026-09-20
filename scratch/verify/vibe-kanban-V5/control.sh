#!/bin/bash
# V5 control replay (ledger #133): identical to vuln.sh minus the trigger —
# the supplied issue belongs to the ATTACKER's own project (legitimate flow).
set -u
BASE=http://127.0.0.1:8081
ATK_TOKEN="${ATK_TOKEN:?}"
OWN_ISSUE="${OWN_ISSUE:?seeded org-A issue UUID required}"
ATK_PROJECT="${ATK_PROJECT:?}"

before=$(curl -s -H "Authorization: Bearer $ATK_TOKEN" "$BASE/v1/issues/$OWN_ISSUE" || true)
curl -s -o /dev/null -X POST "$BASE/v1/workspaces" \
  -H "Authorization: Bearer $ATK_TOKEN" -H 'content-type: application/json' \
  -d "{\"project_id\":\"$ATK_PROJECT\",\"local_workspace_id\":\"canary-ws-2\",\"issue_id\":\"$OWN_ISSUE\",\"name\":\"canary\",\"archived\":false,\"files_changed\":0,\"lines_added\":0,\"lines_removed\":0}"
after=$(curl -s -H "Authorization: Bearer $ATK_TOKEN" "$BASE/v1/issues/$OWN_ISSUE" || true)

if [ "$before" != "$after" ]; then
  echo "CLEAN: own-issue status sync succeeded (intended behaviour)"
  exit 0
fi
echo "UNEXPECTED: legitimate own-issue sync had no effect"
exit 0
