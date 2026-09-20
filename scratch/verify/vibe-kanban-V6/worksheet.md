# vibe-kanban V6 — ledger #134 — cross-org attachment theft (HARNESS-BLOCKED)

Status: candidate #134, **harness-blocked** (2026-09-20). Source-level claim
confirmed at HEAD; no runtime differential possible offline. The gate run
recorded identical BLOCKED output on both sides (stage artefact: `rejected` =
"no demonstrated effect" — NOT a refutation; re-run `verify 134` with infra).
Origin: vk production review finding #2 (archived), [doc-only] until this wave.
HEAD: `d5cbb5380f` (pinned snapshot, unmodified).

## The finding (source-confirmed)

Two source-authorization gaps in `crates/remote/src/routes/attachments.rs`:

1. `confirm_upload` (:231-329): authorizes `payload.project_id` (:236) and any
   destination issue/comment (:240-249), but loads the pending upload with
   `PendingUploadRepository::find_by_id(pool, payload.upload_id)` (:258) with
   **no project_id check** — a foreign pending upload's blob is downloaded and
   re-registered under the attacker's project (:292-305).
2. `commit_issue_attachments` (:332-346) / `commit_comment_attachments`
   (:349-363): authorize only the destination. The SQL in
   `db/attachments.rs:225-240` (`commit_to_issue`) is
   `UPDATE attachments ... WHERE a.id = ANY($2) AND a.issue_id IS NULL AND
   a.comment_id IS NULL` — no project/ownership scoping on the staged
   attachment rows, so any unattached attachment UUID (e.g. one staged in a
   victim project) can be committed to the attacker's issue and then listed
   with download URLs.

Prerequisite: known foreign pending-upload / staged-attachment UUID (not
trivially guessable) — same UUID-knowledge caveat as V5.

## Why harness-blocked

Identical infrastructure blockers as V5 — see
`scratch/verify/vibe-kanban-V5/worksheet.md` ("Why harness-blocked"): remote
crate not buildable offline (missing aws-sdk/azure/opentelemetry/axum-extra
deps), no PostgreSQL, docker denied, AppState not externally constructible.
Additionally, the full confirm path needs an Azure-blob-compatible store
(`state.azure_blob()` gate at attachments.rs:251), which raises the seeding
bar further even with a database.

## Stored replay recipe (runs when a seeded server exists)

Guard: `scratch/vk-harness/remote-probe.sh` (identical BLOCKED text both sides
when no server). Scripts in this directory (UNRUN):

- `vuln.sh` — attacker confirms a victim project's pending-upload UUID against
  their own project + issue, commits, lists: CANARY-COMPROMISED + exit 1 iff
  the foreign file appears in the attacker's listing.
- `control.sh` — identical with the attacker's own pending upload (CLEAN).

## Honest severity note

Source-confirmed CWE-639/CWE-862: the missing checks are unambiguous in the
SQL and route code. Runtime impact (file contents actually served) not
demonstrated; hinges on UUID knowledge and on the Azure-blob path being
configured in production. Doc claims "high"; demonstrated here at code level
only.
