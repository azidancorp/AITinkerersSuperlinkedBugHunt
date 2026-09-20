# vibe-kanban V7 — ledger #135 — unauthenticated worker review callbacks (HARNESS-BLOCKED)

Status: candidate #135, **harness-blocked** (2026-09-20). Routing claim
confirmed at HEAD by direct source trace; no runtime differential possible
offline. The gate run recorded identical BLOCKED output on both sides (stage
artefact: `rejected` = "no demonstrated effect" — NOT a refutation; re-run
`verify 135` with infra).
Origin: vk production review finding #3 (archived), [doc-only] until this wave.
HEAD: `d5cbb5380f` (pinned snapshot, unmodified).

## The finding (source-confirmed)

`crates/remote/src/routes/review.rs:21-32` mounts
`POST /review/{id}/success` (:30) and `POST /review/{id}/failed` (:31) in
`public_router()`. `crates/remote/src/routes/mod.rs:103-110` merges
`review::public_router()` into `v1_public` **without** any middleware, while
`require_session` is layered only onto `v1_protected` (mod.rs:137-140).
The handlers (review.rs:397-450, :454+) parse the UUID, load the review,
`mark_completed`/`mark_failed` it, and then send email via `state.mailer` or
post GitHub PR comments with the app's credentials. No worker credential,
shared secret, or signature is checked anywhere on this path (the crate has a
`shared_key_auth` module, but nothing on the review router references it).
Repeated unauthenticated calls repeat the side effects; review UUIDs already
appear in shared review links (`{base}/review/{uuid}`, review.rs:411).

Weakest prerequisite of the wave: no account needed at all, only a review
UUID.

## Why harness-blocked

Same infrastructure blockers as V5 (see that worksheet): remote crate
unbuildable offline (aws-sdk/azure/opentelemetry/axum-extra/ipnetwork/
urlencoding/reqwest-0.12 missing from cache; private billing git dep), no
PostgreSQL on host, docker socket denied, and `AppState::new` needs
crate-private types so no external router-level harness can be built. A
scratch copy with billing stripped and ts-rs pinned exists at
`scratch/vk-harness/remote` and gets as far as the first missing crates.io
package (`aws-credential-types`). Note the review_success handler itself only
needs pool + mailer — with a lazy pool an unauthenticated POST would return
500 (DB unreachable) rather than 401, which *would* be a valid "reached the
handler past the auth layer" differential vs a 401 on a protected route; the
blocker is purely compiling the crate.

## Stored replay recipe (runs when a seeded server exists)

Guard: `scratch/vk-harness/remote-probe.sh` (identical BLOCKED text both
sides when no server). Stored pair:

- vuln: `remote-probe.sh curl -s -o /dev/null -w '%{http_code}' -X POST
  http://127.0.0.1:8081/v1/review/<seeded-review-uuid>/success`
  — boundary crossed iff status is NOT 401/403 (200 expected with seeded
  review; review rows gets marked completed; mailer canary records a send).
- control: `remote-probe.sh curl -s -o /dev/null -w '%{http_code}'
  http://127.0.0.1:8081/v1/organizations` — protected sibling; 401 expected.

## Honest severity note

Source-confirmed CWE-306: the route mounting is unambiguous at HEAD. Real
impact (forged review outcomes + notification/comment spam sent with app
credentials) not demonstrated at runtime; notification side effects also
depend on configured mailer/GitHub integration. Doc claims "high";
demonstrated here at code level only.
