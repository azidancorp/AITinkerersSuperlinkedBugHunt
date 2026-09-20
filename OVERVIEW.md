# Bug hunt at a glance — 2026-09-20

One-page visual summary of the day's work. Source of truth: `.funnel/funnel.db` +
`claimed-vulnerabilities.md` + `confirmed-vulnerabilities/`.

## The system we built and ran

```
 git history ──> MINE ──> 975 seeds ──────────────┐
                                                  ├──> 136 CANDIDATES
 semgrep ─────> SWEEP ──> 100 raw findings ──────┘        │
                                                          ▼
                                    LLM + human review ── TRIAGE
                                                          │
                       ┌──────────────────────────────────┼───────────────────┐
                       ▼                                  ▼                   ▼
                  25 "tp" (model)                  72 "fp" (model)      3 uncertain
                       │
                       ▼
              DIFFERENTIAL GATE (verify: attack replay vs benign control, ×3)
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   11 VERIFIED     5 REJECTED     3 harness-blocked
        │
        ▼
   9 confirmed write-ups  ──>  human review  ──>  report + submit  (NEXT STEP)
```

## The funnel in numbers

| Stage | Count | Note |
|---|---|---|
| Seeds mined (variant analysis) | 975 | from the repos' own fix history |
| Candidates | 136 | 100 semgrep + 36 research/manual |
| Model-triaged | 100 | 25 tp · 72 fp · 3 uncertain |
| **Verified (gate-proven)** | **11** | every one replayed 3/3 with canaries |
| Refuted by the gate | 5 | rejections are wins too — clean ledger |
| Harness-blocked (not refuted) | 3 | vk cross-org trio; needs a provisioned env |
| Confirmed write-ups | 9 | `confirmed-vulnerabilities/` |
| Submitted | 0 | human gate hasn't run yet |

## The 11 verified findings (plain English)

| # | Target | Finding | In one sentence |
|---|---|---|---|
| 1 | snare | #112 slow-connection DoS | 17 connections sending 1 byte every 3 s (~6 B/s total) stop all webhook delivery — no credentials needed. |
| 2 | snare | #111 unbounded headers | One connection streaming never-ending headers grows daemon memory 1:1 (measured 192 MB in → 204 MB RSS) until OOM. |
| 3 | vibe-kanban | #106 origin check bypass | The only guard on the unauthenticated local API trusts attacker-chosen headers → DNS rebinding gives a web page your files, token, terminal, and agent spawning. |
| 4 | vibe-kanban | #105+#110 reflected XSS | OAuth error page echoes the URL's `error=` param unescaped → one malicious link runs script on the app origin. |
| 5 | WTM ext. | #120+#122 unguarded bridge | Any script on a matched site (FB/X/YT…) can postMessage the extension into overwriting your token, deleting your account, or forging uploads. |
| 6 | WTM ext. | #121 token disclosure | On registration the extension writes your API token into the web page's own localStorage and broadcasts it — permanent leak. |
| 7 | WTM ext. | #131 EU opt-out bypass | Registration stores country as `userData.country` but the EU privacy gate reads `userCountry` → EU users get collected anyway. |
| 8 | WTM ext. | #132 stale token | Upload client reads the token once at startup → after an account switch, uploads keep going out as the previous account. |
| 9 | pizauth | #127 rustls pin | Lockfile pins rustls 0.23.43, inside a published advisory range — supply-chain finding, honestly scoped (no exploit claimed). |

(9 write-ups cover 11 ledger rows: two pairs are duplicates of one bug each.)

## How the day went

```
morning      build the funnel (funnel.py) · code review · 6 hardening fixes
midday       fresh start · re-register 4 targets · mine 975 seeds · sweep 100
early aft    variant swarm reviews ~100 seeds by hand  → 25 research candidates
             triage run (LLM) on semgrep candidates
             independent augmentation swarms: parallel lanes re-review the
             claims, add second opinions, catch dups + a dead-file trap
late aft     RECONCILE: one master list — 42 distinct claims
             EXPECTED-SEVERITY TRIAGE: rank claims by worst-case impact;
             verification effort aimed at the severest first
             wave 4: refute the likely-FPs ......... 5 killed, 1 turned out REAL
             wave 3: register + verify doc-only ... 2 more verified
evening      wave 1 money lane (worst-first) ....... 11 verified total
             second opinions + confirmed write-ups . 9 reports with evidence
```

## Scope discipline held throughout

- Offline except 127.0.0.1 · synthetic canaries only · targets read-only
  (`git status` clean in all 4 repos) · ledger written only via `funnel.py`
- Nothing marked verified without a 3/3 differential replay
- Every report separates MEASURED from INFERRED; nothing submitted yet

## What's next

1. Human review of the 9 write-ups → fill the 14-field reports → replay once
   from clean → `funnel.py submit <id>`
   (report skeletons already exist for #106, #120, #121, #122 in `.funnel/`)
2. Optional: provision an environment (PostgreSQL + crates) for the 3
   harness-blocked vibe-kanban authz claims (#133–#135)
3. Optional: wave 2 leftovers (V3 SSRF, W3/W4 over-collection, P1, S3/S4/S7)
