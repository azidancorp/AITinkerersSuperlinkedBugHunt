#!/bin/bash
set -e
cd /home/azidan/AQL/AI/AITinkerers

python3 funnel.py add vibe-kanban --source variant \
  --title "Missing object-level authz on issue_id: workspace creation authorizes the project but accepts an unchecked issue UUID, letting an authenticated user modify another org's issue status/assignment" \
  --file crates/remote/src/routes/workspaces.rs --line 70 --severity high --cwe CWE-862 \
  --evidence "HEAD d5cbb5380f. crates/remote/src/routes/workspaces.rs:~70 authorizes the supplied project_id but passes caller-supplied issue_id without an ownership check; db/issues.rs sync_issue_from_workspace_created / sync_status_from_local_workspace_merge then change that issue status and assign the caller. Prerequisite: authenticated user + known victim issue UUID. Source-level claim from archived production review #1; not yet replayed."

python3 funnel.py add vibe-kanban --source variant \
  --title "Cross-org attachment theft: upload confirmation loads pending upload by UUID without project check (attachments.rs:258) and commit authorizes destination but not staged source (attachments.rs:338)" \
  --file crates/remote/src/routes/attachments.rs --line 258 --severity high --cwe CWE-639 \
  --evidence "HEAD d5cbb5380f. crates/remote/src/routes/attachments.rs:258 confirms a pending upload by UUID without checking its project_id against the authorized project; :338 commit_to_issue/commit_to_comment (db/attachments.rs) authorize the destination issue/comment but never the staged source attachments, so a foreign staged file can be attached to the caller's own issue and listed with download URLs. Prerequisite: known foreign UUID (not trivially guessable). Source-level claim from archived production review #2; not yet replayed."

python3 funnel.py add vibe-kanban --source variant \
  --title "Unauthenticated worker review callbacks: success/failure callbacks on the public router (review.rs:397) let anyone with a review UUID forge outcomes and trigger notification/comment side effects" \
  --file crates/remote/src/routes/review.rs --line 397 --severity high --cwe CWE-306 \
  --evidence "HEAD d5cbb5380f. crates/remote/src/routes/review.rs:397 mounts review success/failure callback handlers on the public (unauthenticated) router; db/reviews.rs mark_completed/mark_failed change review status and fire emails/GitHub comments with app credentials, repeatedly. Review UUIDs already appear in shared review links. Source-level claim from archived production review #3; not yet replayed."
