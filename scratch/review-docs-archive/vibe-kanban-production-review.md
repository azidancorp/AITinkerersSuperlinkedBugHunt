# Production readiness review

Date: 2026-09-20

Scope: source files within this repository only. Focused on consequential security and data-integrity problems; minor issues and stylistic concerns excluded.

Four substantial problems were identified that should be addressed before deploying the affected cloud features.

## 1. High — Workspace creation can modify another organization's issues

**Evidence:** [`crates/remote/src/routes/workspaces.rs`](crates/remote/src/routes/workspaces.rs), starting at line 70; [`crates/remote/src/db/issues.rs`](crates/remote/src/db/issues.rs), `sync_issue_from_workspace_created` and `sync_status_from_local_workspace_merge`.

Workspace creation authorizes the supplied project but accepts an unchecked `issue_id`. It then invokes synchronization that can change that issue's status and assign the caller. The workspace's merge endpoint can subsequently mark the linked issue Done when its pull-request conditions permit.

**Prerequisite:** an authenticated user with their own project and a known victim issue UUID.

**Impact:** unauthorized modification of another organization's issue status and assignments.

**Recommended fix:** require the linked issue to belong to the authorized project before insertion, and enforce that invariant in subsequent synchronization.

**Regression coverage:** attempt workspace creation with a project in organization A and an issue in organization B. Assert rejection and no workspace, status, or assignment changes. Also verify synchronization rejects any pre-existing inconsistent workspace linkage.

## 2. High — Attachment operations allow cross-organization file theft

**Evidence:** [`crates/remote/src/routes/attachments.rs`](crates/remote/src/routes/attachments.rs), upload confirmation at line 258 and attachment commit at line 338; [`crates/remote/src/db/attachments.rs`](crates/remote/src/db/attachments.rs), `commit_to_issue` and `commit_to_comment`.

Two paths bypass authorization of the source file:

- Upload confirmation loads a pending upload by UUID without checking its `project_id` against the authorized project, then registers its blob under the supplied project.
- Attachment commit checks access to the destination issue or comment but never checks ownership of the supplied staged attachments. The SQL accepts attachments from other projects. Once attached, listing the destination returns download URLs.

**Prerequisite:** a known foreign pending-upload or staged-attachment UUID. These UUIDs are not trivially guessable.

**Impact:** an authenticated user can take another organization's staged file and obtain access through their own project or issue.

**Recommended fix:** authorize the source upload and attachments, and require matching project ownership within the mutation transaction. Apply the checks to both issue and comment destinations.

**Regression coverage:** use separate organizations to test foreign pending-upload confirmation and foreign staged-attachment commits. Assert rejection, unchanged source ownership, and no download access for the caller.

## 3. High — Anyone with a review link can forge worker callbacks

**Evidence:** [`crates/remote/src/routes/review.rs`](crates/remote/src/routes/review.rs), public router and callback handlers starting at line 397; [`crates/remote/src/db/reviews.rs`](crates/remote/src/db/reviews.rs), `mark_completed` and `mark_failed`.

Success and failure callbacks are exposed through the public router without worker authentication. Requests change review status and send emails or post GitHub comments using the application's credentials. Repeated requests repeat those side effects. The review UUID is already present in shared review links.

**Prerequisite:** a known review UUID; notification side effects depend on the configured email or GitHub integration.

**Impact:** forged review outcomes and repeated notifications or GitHub comments attributed to the application.

**Recommended fix:** authenticate worker callbacks and make completion transitions atomic and idempotent.

**Regression coverage:** unauthenticated callbacks must fail without changing state or sending notifications. Repeated and concurrent authenticated callbacks must produce at most one valid state transition and notification.

## 4. High — Attachment cleanup can permanently delete successfully saved files

**Evidence:** [`crates/remote/src/attachments/cleanup.rs`](crates/remote/src/attachments/cleanup.rs), starting at line 68; [`crates/remote/src/routes/attachments.rs`](crates/remote/src/routes/attachments.rs), `delete_attachment`; [`crates/remote/src/db/blobs.rs`](crates/remote/src/db/blobs.rs), `delete`; [`crates/remote/migrations/20260204000000_issue_attachments.sql`](crates/remote/migrations/20260204000000_issue_attachments.sql).

Cleanup selects expired attachments, then deletes them later by ID without rechecking expiry. A concurrent commit can clear expiry and successfully attach the file, only for cleanup to delete it afterward.

There is also a separate count-then-delete race: another request can create a new attachment after the blob's reference count reaches zero but before blob deletion. The database's `ON DELETE CASCADE` then removes the new attachment, and storage deletion removes its file. This pattern occurs in cleanup and explicit attachment deletion.

**Prerequisite:** concurrent attachment commit or creation and cleanup or deletion.

**Impact:** permanent loss of files despite successful save responses.

**Recommended fix:** atomically claim expired attachments and coordinate blob deletion with attachment creation using transactions and appropriate locking.

**Regression coverage:** controlled concurrent tests should pause cleanup after selecting expired records, commit the attachment, and verify it survives. Separately interleave new attachment creation between the zero-reference check and blob deletion, and verify a successfully saved attachment and its file cannot be removed.

## Validation and limitations

- Findings were traced through route handlers, database queries, and repository migrations.
- This was a source-level review, not a runtime reproduction or exhaustive production certification.
- No deployed service was exercised, and no builds or tests were run.
- The review did not modify source files or run the write-mode formatter.
- All inspection stayed within this repository. This report records the findings; no fixes have been implemented.
