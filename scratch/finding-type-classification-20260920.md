# Finding type classification — 2026-09-20

Source reviews:
- `vibe-kanban/production-review.md`
- `pizauth/PRODUCTION_REVIEW.md`
- `Who-Targets-Me/PRODUCTION_REVIEW.md`
- `scratch/snare-review-20260920/review.md` (explicitly incomplete — source-inspection only, probes never ran)

Type legend:
- **Vuln** = security vulnerability
- **Privacy** = data-exposure / compliance issue
- **Data-int** = data-integrity / race bug
- **Reliability** = availability / robustness bug
- **Awkward** = design / state-management flaw
- **Minor** = low-impact config / ops issue

Verification legend:
- **probed** = reproduced in an isolated probe (mocked browser/API or synthetic fixtures)
- **source-only** = traced through source, never executed
- **candidate** = unverified claim awaiting differential-gate replay

Note: only Who-Targets-Me findings were probed. The vibe-kanban and pizauth
reviews are also source-only ("source-level review, not a runtime
reproduction"; pizauth execution was blocked), so their vuln labels carry the
same evidentiary status as snare's — higher-confidence narratives, no replay.
The pizauth review's "no Rust toolchain is configured" claim conflicts with the
same-day snare review, which ran Rust 1.97.1 on this machine; pizauth findings
were buildable and probeable in principle.

## vibe-kanban — mostly real vulns (strongest findings)

| # | Finding | Type | Verify |
|---|---|---|---|
| 1 | Workspace creation can modify another org's issues | **Vuln** — broken access control; missing object-level authorization (CWE-862/639 family, not reference guessing — UUIDs not trivially guessable) | source-only |
| 2 | Attachment ops allow cross-org file theft | **Vuln** — missing object-level authorization on the source file; file theft | source-only |
| 3 | Unauthenticated worker review callbacks | **Vuln** — missing authn, forged state + notification spam; lowest prerequisite bar (review UUID already in shared links) | source-only |
| 4 | Attachment cleanup race deletes saved files | **Data-int** — TOCTOU race, not attacker-driven | source-only |

## pizauth — one vuln, rest reliability/awkward

| # | Finding | Type | Verify |
|---|---|---|---|
| 1 | Unbounded `read_line()` + unbounded threads on callback server | **Vuln** — unauthenticated DoS (CWE-400); loopback-only by default limits exposure, remote reachability is deployment-dependent | source-only |
| 2 | Short-lived tokens → endless refresh loop | **Reliability** — provider-triggered rate-limit churn (tokens shorter than the 90s refresh lead); no attacker | source-only |
| 3 | Reminder notification discards successful auth | **Awkward** — state-management race; correctness bug with user-visible auth failure | source-only |
| 4 | One stalled local client blocks all CLI requests | **Reliability** — local-only DoS, daemon-wide impact incl. `shutdown` (no CLI recovery); source rates it Medium | source-only |
| 5 | Cargo.lock pins rustls 0.23.43 inside RUSTSEC-2026-0285 affected range | **Vuln** — known-vulnerable dependency (CWE-1104, supply-chain); advisory-tempered impact (transcript stays authenticated; needs malicious peer); first differential-gate-verified row. Detail: `pizauth-rustls-advisory-20260920.md` | verified (pin; candidate #127) |

## Who-Targets-Me — vulns + privacy, plus one minor

| # | Finding | Type | Verify |
|---|---|---|---|
| 1 | Websites can change account/consent settings | **Vuln** — missing sender authorization (worst one here; effectively extension account takeover) | probed |
| 2 | Registration credentials leak to unrelated active tab | **Vuln** — token disclosure | probed |
| 3 | Uploads stay authenticated as previous account | **Data-int** — stale-token logic bug; uploads misattributed (privacy impact in a data-collection context) | probed |
| 4 | New EU users bypass collection exclusion | **Privacy/Compliance** — collection-exclusion logic bug; the GDPR framing is an inference (source shows an EU exclusion mechanism, not a named regulation) | probed |
| 5 | Facebook collector uploads whole GraphQL response incl. personal posts | **Privacy** — over-collection / data leak; actual exposure depends on response contents | probed |
| 6 | Firefox manifest omits inline collector | **Minor** — config gap, ads silently missed, no security impact | source-only |
| — | `OFFLINE=true` publish workflow embeds localhost endpoints | **Minor/Deployment caveat** — informational only | source-only |

## snare — all unverified candidates (no runtime proof yet)

| # | Finding | Type | Verify |
|---|---|---|---|
| 1 | Unbounded request lines/headers before auth | **Vuln (claimed)** — unauthenticated memory-exhaustion DoS; not reproduced | candidate |
| 2 | Per-read timeout, no overall deadline → slow-client worker exhaustion | **Vuln (claimed)** — slowloris-style DoS; not reproduced | candidate |
| 3 | Job timeout doesn't kill process group, zero-timeout busy loop | **Reliability** — needs a misbehaving configured command, not remote-triggered | candidate |
| 4 | Stale unix socket path blocks restart | **Minor/Ops** — lifecycle bug, TCP mode unaffected | candidate |

## Summary

Counts use one bucket per row (19 rows total):

- 6 source-confirmed vulns: vk1–3, pizauth 1, WTM 1–2 (only WTM 1–2 runtime-probed)
- 2 unverified vuln candidates: snare 1–2
- 2 data-integrity: vk4, WTM 3
- 2 privacy/compliance: WTM 4–5
- 1 awkward: pizauth 3
- 3 reliability: pizauth 2, pizauth 4, snare 3
- 3 minor/informational: WTM 6, OFFLINE workflow, snare 4
- Nothing visual anywhere — all findings are backend/logic level.
- Caveat: the two snare "vulns" are only source-level claims — candidates, not
  findings, until replayed through the differential gate. Per workspace rules,
  nothing unverified ships; every finding needs a clean-state replay before
  submission, including the source-only vibe-kanban and pizauth vulns.

## Revision note

2026-09-20 (later session) — added pizauth 5: rustls 0.23.43 pin /
RUSTSEC-2026-0285, candidate #127, differential gate YES (from
external-agent reconciliation). Source-confirmed vuln count 6 → 7; it is the
first row verified through the differential gate (the pin fact — advisory
exploitability in-target remains unproven). Detail in
`pizauth-rustls-advisory-20260920.md`.

2026-09-20 — corrected after review: vk1/vk2 relabelled from "IDOR" to missing
object-level authorization; pizauth 2 retyped Reliability with provider-trigger
wording; pizauth 4 retyped Reliability (was Minor/Reliability); WTM 3 retyped
Data-int (was Privacy/Integrity); verification column added; summary recounted
(6 + 2 candidates / 2 / 2 / 1 / 3 / 3 — previous "8 genuine security vulns"
did not reconcile with the tables).
