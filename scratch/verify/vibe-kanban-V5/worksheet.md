# vibe-kanban V5 — ledger #133 — cross-org issue mutation via unchecked issue_id (HARNESS-BLOCKED)

Status: candidate #133, **harness-blocked** (2026-09-20). Source-level claim
confirmed at HEAD; no runtime differential was possible in this offline
workspace. The gate run recorded for this row shows identical BLOCKED output
on both sides (stage artefact: `rejected` = "no demonstrated effect" — this is
NOT a refutation; re-run `verify 133` once infra exists).
Origin: vk production review finding #1 (archived), [doc-only] until this wave.
HEAD: `d5cbb5380f` (pinned snapshot, unmodified).

## The finding (source-confirmed)

`crates/remote/src/routes/workspaces.rs:70` — `create_workspace` calls
`ensure_project_access(pool, ctx.user.id, payload.project_id)` only. The
caller-supplied `issue_id` is never checked against the authorized project.
It is stored on the workspace (:72-86) and then
`IssueRepository::sync_issue_from_workspace_created(pool, issue_id,
ctx.user.id)` runs (:92-94), which (`crates/remote/src/db/issues.rs:641-668`)
moves that issue to "In progress" (and cascades to its parent) when this is
the issue's first workspace — regardless of which organisation owns the issue.
The merge endpoint `sync_issue_status_from_local_merge`
(routes/workspaces.rs:47-49) offers a follow-on path to mark the linked issue
Done. Prerequisite: authenticated user with own project + known victim issue
UUID (UUIDs not trivially guessable; the desktop client/sync paths expose
issue UUIDs to org members, and shared links leak review/issue identifiers).

## Why harness-blocked

1. `crates/remote` is excluded from the root cargo workspace
   (`vibe-kanban/Cargo.toml:35`) and is its own workspace.
2. Offline build fails at dependency resolution/fetch:
   - private `billing` git dep (ssh://github.com/BloopAI/vibe-kanban-private)
     unfetchable offline — worked around in a scratch copy
     (`scratch/vk-harness/remote`, dep stripped; feature is off by default and
     `src/billing.rs` no-ops without it);
   - `ts-rs` git branch unpinned — worked around by pinning rev `b5c8277`
     from the original `Cargo.lock`;
   - then hard-blocked: `aws-credential-types`, `aws-sdk-s3`, `azure_core`,
     `azure_storage_blob`, `azure_identity`, `opentelemetry*`,
     `tracing-opentelemetry`, `axum-extra`, `ipnetwork`, `urlencoding`,
     `reqwest 0.12` (otel-reqwest) are all absent from the offline cargo
     cache. Stubbing these would mean editing the very route files under
     test — rejected on fidelity grounds.
3. No PostgreSQL on host (the server requires PG with `wal_level=logical` plus
   migrations); docker socket is permission-denied.
4. `AppState::new` requires crate-private types (`JwtService`,
   `OAuthHandoffService`, `OAuthTokenValidator`), so an external router-level
   harness cannot construct it either.

## Stored replay recipe (runs when a seeded server exists)

Guard `scratch/vk-harness/remote-probe.sh` prints byte-identical BLOCKED text
on both sides when no server listens on 127.0.0.1:8081; otherwise it executes
the wrapped command. Scripts in this directory (UNRUN):

- `vuln.sh` — as attacker (org A): create workspace with org-B issue UUID;
  CANARY-COMPROMISED + exit 1 iff the org-B issue changed.
- `control.sh` — identical with an org-A issue (legitimate sync; CLEAN).

Seeding needed: two orgs A/B, attacker JWT for A, issue in B, project in A —
insert via SQL fixtures against the migrated schema.

## Honest severity note

Source-confirmed missing object-level authorisation (CWE-862/639): the
mutation path from an authorized-project request to a foreign issue's status
is direct and unconditional. Not demonstrated at runtime; exploitability in
production also depends on UUID knowledge and on the frontend never offering
this flow (the API is the trust boundary, not the UI). Severity "high" is the
doc's claim; demonstrated impact here is code-level only.
