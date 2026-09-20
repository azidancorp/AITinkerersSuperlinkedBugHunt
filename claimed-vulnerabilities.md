# Master inventory of claimed vulnerabilities — reconciled 2026-09-20

The ONE comprehensive list of every vulnerability claimed by any lane. The ledger
(`.funnel/funnel.db`) remains the source of truth for status; this doc is the
human-readable index across all lanes and artifacts.

Sources reconciled: ledger #1–#136 (current `.funnel/funnel.db`), 17 parked rows
(`.funnel.bak-20260920T130409Z`), triage run `triage-qwen38-20260920T134351Z`,
`scratch/review-docs-archive/{vibe-kanban,pizauth,Who-Targets-Me}-*.md`,
`scratch/snare-review-20260920/review.md`, variant-lane report + snare
notes/rejections, classification doc (`scratch/finding-type-classification-20260920.md`),
replay harnesses and worksheets (`scratch/verify/`), verify-lane results.

Legend: **[doc-only]** never registered · **[dup]** multi-lane registrations merged ·
**[doubted]** originating lane later questioned it · **[refuted]** traced and rejected
at HEAD · **[parked-only]** backup row, no modern equivalent ·
**[harness-blocked]** source-confirmed but no runnable replay yet (NOT refuted).

## snare

- **S1 — Pre-auth unbounded HTTP request-line/header reads → memory exhaustion + connection-slot starvation** [dup] · `src/httpserver.rs:340-361` (`parse_get` header loop; body cap 64 KiB only) · claimed high/med, CWE-400 · ledger **#111** (manual, high) — **VERIFIED — differential 2/2**; **#116** (variant, med) is a dup whose attached cmds actually described the S2 measurement (prose, never ran) — #111 is canonical; parked #103 (same, :329); review-doc finding 1 · Replay (`scratch/s1_headerflood.py` + `s1-{vuln,control}.sh`): ONE connection floods 192 MiB of header lines → daemon RSS 5→209 MiB (~1.06× input, 2.5 s), released back to 5 MiB on disconnect; control delivers the SAME 193 MiB as well-formed 32 KiB-body requests through the capped body path → RSS flat, `CLAIM_EFFECT=none` — byte volume is not the cause, the uncapped header path is. Connection-slot facet is S2, verified separately. The variant-lane coordinator's confirmation stands.
- **S2 — Per-read timeout only, no overall request deadline → slow-client exhaustion of all HTTP workers** · `src/httpserver.rs:156` (socket timeouts), accept loop `:138-143` · claimed high, CWE-400 · ledger **#112** (manual); review-doc finding 2 · status: **VERIFIED** (differential gate, 2026-09-20 — resolves the inter-lane disagreement in favour of the finding: a few unauthenticated slow clients can occupy all 16 workers) · Previously [doubted]: the variant lane had concluded thread-parking was bounded by design; the gate disagreed.
- **S3 — Job timeout is SIGTERM-only to direct child; pipe-inheriting descendants pin the job slot** · `src/jobrunner.rs:216-233` (completion needs stderr_hup && stdout_hup; zero-timeout poll busy-loop after expiry) · claimed high (ledger) / reliability (classification), CWE-400 · ledger **#113** (manual); parked #104 (same, med) · status: untriaged, harness prepared-not-run · Hung job's grandchildren keep pipes open → Sequential queue starves that repo; needs a misbehaving configured command, not remote-triggered. Variant-lane addendum judged it consistent with code.
- **S4 — Stale Unix socket path blocks restart (plus 0777-and-umask socket perms)** [doubted] · `src/httpserver.rs:37-40` (`UnixListener::bind` direct, no stale recovery) · claimed high, CWE-732 · ledger **#114** (manual); parked #105 · status: untriaged, harness prepared-not-run · Ordinary stop/restart in Unix-socket mode fails with address-in-use. *Doubt:* variant lane + classification both rate it availability-only/minor-ops; "high" looks inflated. The umask-perms aspect was separately rejected as a config-trust hardening gap.
- **S5 — HTTP request smuggling (dup Content-Length last-wins, TE ignored, obs-fold)** [refuted] [parked-only] · `src/httpserver.rs:362` · claimed high, CWE-444 · parked #102 only, never re-registered · Dead class at HEAD: one request per connection, no keep-alive, read side shut after body — desynced bytes are never reinterpreted.
- **S6 — Unbounded queue growth for unsigned requests when repo has no secret** [refuted] [parked-only] · `src/httpserver.rs:277` · claimed high, CWE-770 · parked #106 only · Documented tradeoff (man page recommends secrets "in all cases"); 64 KiB body + 16-thread caps bound the rest.
- **S7 — `Queue::pop` selects newest (not oldest) pending job across repos — FIFO inversion** · `src/queue.rs:88-92` (inverted `req_time` comparison contradicts comment + `snare.conf.5:202`; present since queue kinds 998931c) · claimed low · ledger **#117** (variant) · status: untriaged, no harness · Sustained attacker webhook load starves legitimate repos' queued jobs; timing-based tests don't catch it.

## pizauth

- **P1 — OAuth callback HTTP/HTTPS listener: unbounded `read_line`, no socket timeouts, one detached thread per connection** [dup] · `src/server/http_server.rs:283,302,409-414` (`parse_get`; 16 KB cap checked *between* reads) · claimed med (ledger) / high (review doc), CWE-400 · ledger **#109** (med) + **#118** (med, has cmd pair); review-doc finding 1 · status: untriaged; turnkey loopback replay described in-ledger (#109) and cmds attached (#118) · Unauthenticated client dribbles newline-free lines / parks threads → memory/thread/FD exhaustion; loopback default limits exposure, remote if configured.
- **P2 — `startup_cmd` runs via `$SHELL -c` with no timeout; systemd `Type=notify` never reports Ready** · `src/server/mod.rs:334-358` (unbounded `child.wait()`; sole sibling missed by PR #73 timeouts sweep) · claimed low, CWE-400 · ledger **#108** · status: untriaged · Hung startup command wedges daemon startup; child never reaped.
- **P3 — Control socket: unbounded `read_to_end` + serial accept loop → memory DoS / one stalled local client blocks all CLI incl. `shutdown`** [dup] · `src/server/mod.rs:89` (read), `:455` (serial loop) · claimed med, CWE-400 · ledger **#130** (restored parked #110); review-doc finding 4 (stall aspect) · status: untriaged, no harness · Local client that stalls before EOF blocks every subsequent `show/dump/reload/shutdown`.
- **P4 — Control socket: no peer-credential check, perms left to umask** · `src/server/mod.rs:444` · claimed med, CWE-306 · ledger **#128** (restored parked #109) · status: **REJECTED** (differential gate, wave-4 refutation 2026-09-20 — confirms the variant-lane trace: `cache_path()` enforces 0700 on both components and fails closed) · Claim contradicted an already-recorded rejection; the gate agreed.
- **P5 — Token dump encryption uses hardcoded published ChaCha20 key** [doubted] · `src/server/state.rs:39` · claimed high, CWE-321 · ledger **#129** (restored parked #108) · status: untriaged · *Doubt:* variant lane explicitly declined to register this class — `pizauth.1:38-42` documents the key as trivially recoverable with a user-facing warning; near-certain FP.
- **P6 — Reserved OAuth param guard bypassable via query string in `auth_uri`** · `src/config.rs:316` · claimed high, CWE-20 · ledger **#126** (restored parked #107) · status: untriaged, no harness · Config-supplied auth URI can smuggle reserved params past the guard.
- **P7 — Duplicate account blocks silently overwrite (last-wins) in `Config::from_str`** · `src/config.rs:102` (every other duplicated field is a hard error) · claimed low · ledger **#119** (has cmd pair) · status: untriaged · Config ambiguity; security impact unclear.
- **P8 — Cargo.lock pins rustls 0.23.43 inside RUSTSEC-2026-0285 range (>=0.23.13,<0.23.45)** · `Cargo.lock` · claimed med, CWE-1104 · ledger **#127** (manual) · status: **VERIFIED — first differential-gate-verified row** (differential: `grep rustls` vs `grep ring` on Cargo.lock — a presence/pin check, not an exploit replay) · Full finding record incl. affected range, where rustls sits on pizauth's paths (Cargo.toml:42, http_server.rs:428-483, ureq outbound), and the advisory's own impact-tempering quote: `scratch/pizauth-rustls-advisory-20260920.md` · Do NOT escalate to "on-path attacker breaks TLS" at report time. Pre-submission: `funnel.py report 127`.
- **P9 — Short-lived provider tokens → continuous refresh loop** [doc-only] · `src/server/refresher.rs:373` (`expiry - 90s` lead; 60 s tokens immediately overdue) · claimed high in doc, retyped Reliability · pizauth PRODUCTION_REVIEW #2 only · Provider-triggered rate-limit churn; no attacker.
- **P10 — Reminder notification silently discards successful authentication** [doc-only] · `src/server/notifier.rs:89` + `src/server/http_server.rs:201` (state replacement changes AccountId mid-exchange; one-use code consumed, account stuck pending) · claimed med, retyped Awkward/state-race · pizauth PRODUCTION_REVIEW #3 only.

## vibe-kanban

- **V1 — Reflected XSS in OAuth handoff error page** [#105 canonical; #110 is the same claim — do not file separately] · `crates/server/src/routes/oauth.rs:163` (+`:435`; raw `error` query param formatted into text/html before handoff-state check; GET sends no Origin so `validate_origin` passes) · claimed high, CWE-79 · ledger **#105** + **#110** (near-identical titles, evaded dedupe key) · status: **VERIFIED — differential YES on both rows** (2026-09-20, second verified vk row): verbatim HEAD `oauth.rs` spans (5/5 fidelity-checked) + byte-identical `origin.rs` in `scratch/verify/vibe-kanban-V1/` behind the production layer wiring — 3/3 payloads (`<svg onload>`, `<script>`, `<img onerror>`) reflected unescaped into `text/html` 400 with no-Origin GET (link-click shape); 4/4 controls clean (benign error, missing-code branch, cross-Origin 403, missing-`handoff_id` Query rejection) · Accuracy: #105's original curl omitted required `handoff_id` and could never have fired (Query rejection) — claim unaffected with any valid UUID; token-theft escalation via `/api/auth/token` is source-confirmed only (needs a logged-in remote deployment) · confirmed report: `confirmed-vulnerabilities/vibe-kanban-oauth-handoff-reflected-xss.md` · Attacker link reflects arbitrary JS in the app's origin.
- **V2 — Origin validation accepts `Origin == Host` and no-Origin requests → DNS-rebinding bypass of the unauthenticated local API** · `crates/server/src/middleware/origin.rs:41,45,59,113` (fix commit 346db013 itself flawed) · claimed high, CWE-346 · ledger **#106** · status: **VERIFIED — differential 3/3 YES** (2026-09-20, first verified vk row): real HEAD `origin.rs` compiled **byte-identical** in `scratch/verify/vibe-kanban-V2/` behind the production `ValidateRequestHeaderLayer` wiring (routes/mod.rs:74-76 mirrored exactly; `relay_client::RELAY_HEADER` const copied verbatim) — 4/4 attacker shapes reached the handler (no-Origin; Origin==Host same-port; case-variant via the :74-79 OriginKey path; `x-vk-relayed: 1` skip) while 3/3 controls 403 (honest cross-origin, `Origin: null`, cross-port rebinding). Full server binary unbuildable offline (aws-lc-sys→bindgen, no libclang C API), so downstream impact (filesystem listing, PUT /config, GET /auth/token, /terminal/ws, POST /workspaces/start w/ attacker executor_config+prompt) is source-confirmed only · Accuracy: `x-vk-relayed` skip does NOT defeat `require_relay_request_signature` on signed routes (401 backstop) but DOES fully expose `relay_auth/*` + `host_relay` proxy (outside the signature layer); header not a practical web vector (CORS preflight + no ACA headers; "forbidden header" reasoning corrected on independent review 2026-09-20) — web vectors are no-Origin GET and same-port Origin==Host rebinding · worksheet + harness: `scratch/verify/vibe-kanban-V2/` · independent review CONFIRM-WITH-EDITS applied: `scratch/review-v2-independent-20260920.md`.
- **V3 — Preview proxy forwards `/api/preview/{port}` to `http://localhost:{port}` for any client port** · `crates/preview-proxy/src/api.rs:43` · claimed med, CWE-918 · ledger **#107** · status: untriaged, cmd pair attached · SSRF to arbitrary loopback services.
- **V4 — AppleScript injection in macOS push notification via agent-settable workspace name** [doubted] · `crates/services/src/services/notification.rs:159` (workspace name flows into `osascript -e` string) · claimed high · ledger **#115** · status: untriaged, no harness, *never reviewed by any other lane*.
- **V5 — Workspace creation can modify another org's issues (missing object-level authz on `issue_id`)** [harness-blocked] · `crates/remote/src/routes/workspaces.rs:70` + `crates/remote/src/db/issues.rs` · claimed high (CWE-862/639 family) · ledger **#133** · status: re-confirmed at source HEAD `d5cbb5380f` (`workspaces.rs:70` authorizes only `project_id`, then mutates unchecked `issue_id` via `sync_issue_from_workspace_created`, `db/issues.rs:641`) but HARNESS-BLOCKED: `remote` is excluded from the root workspace, private `billing` dep unfetchable offline, `aws-sdk-s3`/`azure_*`/`reqwest 0.12` etc. absent from the offline cargo cache, no PostgreSQL/docker · **CAUTION: stage reads `rejected` via a BLOCKED-guard replay — that is "no demonstrated effect", NOT a refutation**; verify_log carries the BLOCKED note; recipe scripts + full blocker trail in `scratch/verify/vibe-kanban-V5/` · Authenticated user + known victim issue UUID → unauthorized status/assignment changes.
- **V6 — Attachment ops allow cross-org file theft** [harness-blocked] · `crates/remote/src/routes/attachments.rs:258,338` + `db/attachments.rs` (pending-upload confirmed without project check; `commit_to_issue` SQL `db/attachments.rs:233-239` has no ownership scoping) · claimed high · ledger **#134** · status: HARNESS-BLOCKED, same blockers and same rejected-stage caution as V5; `scratch/verify/vibe-kanban-V6/`.
- **V7 — Unauthenticated worker review callbacks (forged outcomes + notification/comment spam)** [harness-blocked] · `crates/remote/src/routes/review.rs:397` (`review.rs:30-31` callbacks sit in `public_router()`, merged into `v1_public` with no middleware — `routes/mod.rs:108`; `require_session` wraps only `v1_protected` `:137-140`) · claimed high · ledger **#135** · status: HARNESS-BLOCKED, same blockers and same rejected-stage caution as V5; `scratch/verify/vibe-kanban-V7/` · Lowest prerequisite bar of the trio.
- **V8 — Attachment cleanup race permanently deletes successfully saved files** [doc-only] · `crates/remote/src/attachments/cleanup.rs:68` (+ count-then-delete race with `ON DELETE CASCADE`) · claimed high, retyped Data-integrity TOCTOU · production-review.md #4 only.
- **V9 — Quadratic stdout/ACP log normalizer in cursor executor** [parked-only] · `crates/executors/src/executors/cursor.rs:395` · claimed high, CWE-400 · parked #111 only; not re-reviewed this session.
- **V10 — `ready_chunks` 1024 cap leaves replay superlinear for many-chunk transcripts** [parked-only] · `crates/utils/src/msg_store.rs:161` · claimed med, CWE-400 · parked #112 only.
- **V11 — GitHub App installation token exposed in `git clone` argv** [parked-only] · `crates/remote/src/github_app/service.rs:291` · claimed med, CWE-214 · parked #113 only.
- **V12 — GitHub Actions `${{ github.* }}` interpolation in `run:` steps (script injection)** · `pre-release.yml:64` (#20), `publish.yml:161` (#59), `relay-deploy-prod.yml:44` (#61), `remote-deploy-prod.yml:49` (#63) · semgrep ERROR · **triage verdict tp** · Out-of-scope CI workflows, not shipped code.
- **V13 — 15× unpinned mutable action refs (supply-chain)** · all in `pre-release.yml` (#22–#36, #44) · semgrep WARNING · **tp**.
- **V14 — `postMessage(...,"*")` in preview-proxy dev scripts + web-core bridges** · `click_to_component_script.js:19` (#73), `devtools_script.js:11` (#74), `eruda_init.js:10` (#75) — **tp**; `vscode/bridge.ts:295` (#89), `previewBridge.ts:132` (#95) — **uncertain**.
- **V15 — `child_process` spawned from function-arg `bin` in npx-cli** · `npx-cli/src/cli.ts:218` (#76) · semgrep ERROR · **uncertain**.

## Who-Targets-Me

- **W1 — Unvalidated page→background message bridge: any same-page script drives privileged handlers** [dup] · `src/daemon/index.js:10` forwards all same-window postMessage verbatim; `src/shared/handlers/onMessageEventHandler.js:14,55,75` no sender/type gating · claimed high, CWE-346 · ledger **#101** + **#120** (dup, has cmd pair) + **#122** (SEND_RAW_LOG forgery facet, med, `:76`); parked #114; WTM review #1 (**probed**: token replacement + consent flip reproduced) · status: **VERIFIED** (differential gate 2026-09-20): real HEAD `src/daemon/index.js` + `src/shared/handlers/onMessageEventHandler.js` replayed in `node:vm` — `storeUserToken` overwrites `general_token` with attacker canary (1/1 YES, #120) and `SEND_RAW_LOG` accepts attacker-forged rawlog (1/1 YES, #122), while benign unrelated messages leave state unchanged; confirmed-vulnerabilities evidence next to this file · Capabilities: `general_token` overwrite, silent account deletion, consent change, forged rawlog submission, extension-reload DoS.
- **W2 — registrationFeedback writes fresh bearer token into page-origin localStorage + broadcasts `postMessage("*")`** [dup] · `src/daemon/index.js:15-16`; token is the `submit-rawlogs` Authorization credential; feedback goes to *whichever tab is active* (`postMessageToFirstActiveTab.js:3-4`) · claimed high, CWE-312 · ledger **#102** + **#121** (canonical, has cmd pair); parked #115; review #2 (probed); semgrep **tp** #10/#11 are the same `postMessage "*"` sink · status: **VERIFIED** (3/3 differential YES, 2026-09-20): real HEAD `daemon/index.js` in a node:vm sandbox — `registrationFeedback` message → canary token in page-origin localStorage AND page postMessage log; benign control writes nothing. Report `.funnel/report-121.md` (14 fields filled); worksheet + replication brief `scratch/verify/Who-Targets-Me-W2/` · CAUTION: `wtm-verify/c115-*.mjs` import the dead duplicate `src/contents/index.js` — the gate ran on the live sink only · Disclosure to every script on the active matched tab.
- **W3 — Facebook collector uploads entire GraphQL response when any `sponsored_data` marker present** [dup] · `src/daemon/collector/platforms/facebook/handleApiResponse.js:28-34` · claimed med, CWE-359 · ledger **#103** + **#124**; review #5 (probed with synthetic response; personal post retained in payload) · status: untriaged; no dedicated harness file (probe described in doc only) · Over-collection of organic/personal content beyond stated purpose.
- **W4 — YouTube advert context uploads raw page URL incl. `?search_query=`** [dup] · `src/daemon/collector/platforms/youtube/getAdvertContext.js:7,13` (twitter/facebook/instagram all call `removeQueryParamsFromUrl`; YouTube omits it) · claimed med (parked: high, CWE-598) · ledger **#104** + **#123**; parked #116 · status: untriaged; harness `wtm-verify/c116-youtube-vuln` + `c116-facebook-control` ready · Leaks user search terms to backend.
- **W5a — EU collection-exclusion bypass for newly registered users (country written to `userData.country`, gate reads `userCountry`)** · `src/shared/handlers/onMessageEventHandler.js:69-71` vs `handleUserRegistration.js:11-12` · claimed P1 (Privacy/compliance) · ledger **#131** · status: **VERIFIED** (3/3 differential YES, 2026-09-20): real HEAD `onMessageEventHandler.js` in a node:vm sandbox — post-registration storage state of a fresh German user (`userData.country="de"`, `userCountry` absent) collected a SEND_RAW_LOG (CANARY-COMPROMISED); identical state plus `userCountry="de"` suppressed it (CLEAN). The single trigger is the key mismatch between what registration writes and what the gate reads · worksheet + harness: `scratch/verify/Who-Targets-Me-W5a/`.
- **W5b — EU rawlog pause never engages for tokenless users (TypeError on `general_token.length`)** [refuted] · `src/shared/handlers/handleUserCountry.js:5` · claimed med, CWE-754 · ledger **#136** · status: **REJECTED** (wave-4 refutation 2026-09-20 — confirms the anticipated FP: fix c09e0be `if (!general_token) return ""` is an ancestor of HEAD).
- **W6 — `checkScripts` uses undefined variable `s` in `removeChild` → ReferenceError** [doubted] · `src/shared/handlers/handleScriptInjection.js:15` · claimed low · ledger **#125** only · *Doubt:* the variant lane explicitly listed this as deliberately-NOT-registered (dead code, no security impact); a later lane registered it anyway.
- **W7 — `getPlatform()` hostname suffix match lacks dot boundary (`eviltwitter.com` matches)** [refuted] [parked-only] · `platforms/platforms.js:17` · claimed low, CWE-20 · parked #118 only · Unreachable at HEAD — site-matches.json constrains injection hosts.
- **W8 — API client captures auth token once; account changes leave uploads authenticated as previous account** · `src/shared/api/app.js:7-15` · claimed P1 (Data-integrity; uploads misattributed), CWE-613 · ledger **#132** · status: **VERIFIED** (3/3 differential YES, 2026-09-20): real HEAD `app.js` in a node:vm sandbox — after a canary-token A→B account switch the outgoing `Authorization` header still carried A (CANARY-COMPROMISED); without the switch it carried the current token (CLEAN). Demonstrated impact: uploads misattributed to the previous account + stale-credential use; backend acceptance NOT demonstrated (do not claim it) · worksheet + harness: `scratch/verify/Who-Targets-Me-W8/`.
- **W9 — Firefox manifest omits `inline-collector.js` from web-accessible resources** [doc-only] · `src/build/v2.manifest.template.json:22-27` · P2 minor (functional, no security impact) · review #6 only.
- **W10 — Publish workflow builds with `OFFLINE=true`, embedding localhost API/results endpoints** [doc-only] · `.github/workflows/main.yml:23` · informational/deployment caveat · review "Deployment caveat" only.

## Summary

| Target | Distinct claims | Registered | Harness-ready / probed | Doc-only | Parked-only | Verified |
|---|---|---|---|---|---|---|
| snare | 7 (S1–S7; 2 refuted) | 6 — #111–114, #116, #117 | **S1+S2 verified (2/2 and 3/3 replays)**; S3, S4 prepared | 0 | S5, S6 | **2 (#111/S1, #112/S2)** |
| pizauth | 10 (P1–P10) | 8 — #108, #109, #118, #119, #126–#130 | P1, P7 have cmds | P9, P10 | none | **1 (#127/P8)** |
| vibe-kanban | 15 (V1–V15) | 10 research (#105–107, #110, #115, #133–135) + 23 semgrep | V1–V3 have cmd pairs; V5–V7 harness-blocked | V8 | V9–V11 | **2 (#106/V2, #105+#110/V1)** |
| Who-Targets-Me | 10 (W1–W10; 2 refuted) | 12 — #101–104, #120–125, #131, #132, #136 | W1, W4 harnessed; W3, W5a, W8 probed; W2 verified | W9, W10 | W7 | **5 (#120/#122/W1, #121/W2, #131/W5a, #132/W8)** |
| **Total** | **42 canonical claims** | 36 research + 25 semgrep-triaged | ~12 | 5 | 6 | **8 claims / 9 ledger rows** |

## Cross-cutting flags

1. **Verified so far (9)**: #127/P8 (pizauth rustls pin — presence check, honestly
   scoped), #112/S2 (snare slow-client worker exhaustion — the gate resolved an
   inter-lane disagreement), **#111/S1 (snare pre-auth unbounded header memory —
   exploit replay 2/2: one connection, 192 MiB of headers → RSS 5→209 MiB in
   ~2.5 s, freed on disconnect; control pushes the SAME volume through the
   64 KiB-capped body path and stays flat; harness `scratch/s1_headerflood.py`,
   #116 is the dup whose cmds actually described S2)**,
   #131/W5a (WTM EU collection-exclusion bypass — real HEAD source replayed in node:vm), #132/W8 (WTM stale-token upload
   misattribution — backend acceptance NOT demonstrated, don't claim it),
   **#121/W2 (WTM registrationFeedback bearer-token disclosure — canary token
   written to page-origin localStorage + broadcast `postMessage "*"` 3/3 on the
   live sink `daemon/index.js`; disclosure demonstrated, exfiltration/backend
   use NOT — don't claim them; report filled: `.funnel/report-121.md`)**,
   **#120/#122/W1 (WTM unvalidated page→background bridge — real HEAD
   `daemon/index.js` + `onMessageEventHandler.js` replayed in `node:vm`;
   `storeUserToken` overwrites `general_token` 1/1 YES, `SEND_RAW_LOG` accepts
   attacker-forged rawlog 1/1 YES; evidence in
   `confirmed-vulnerabilities/wtm-w1-evidence/`)**,
   **#106/V2 (vibe-kanban origin-validation bypass — real HEAD origin.rs
   replayed byte-identical: 4/4 attacker shapes bypass, 3/3 controls blocked,
   gate 3/3 YES; downstream RCE chain source-confirmed; see
   `scratch/verify/vibe-kanban-V2/worksheet.md` for accuracy notes before
   reporting)**.
   All but #121 still need their report; `funnel.py report <id>` + human review
   is the next step for each (#121's 14-field report is filled).
2. **Money lane now verified**: V1 (OAuth handoff reflected XSS) verified
   2026-09-20 alongside V2, W1, and W2 (see 1) — differential YES on #105/#110,
   harness + confirmed report in `confirmed-vulnerabilities/vibe-kanban-oauth-handoff-reflected-xss.md`.
   No verified vk/WTM claim remains without a verification trail; reports are the
   remaining work.
3. **Refuted this round (valuable — ledger is cleaner)**: #128/P4 and #136/W5b
   gate-rejected; P5 (#129), W6 (#125), V4 (#115) refuted by code trace (no
   honest offline replay exists; they await a triage run to set verdict=fp) —
   full dispositions in `scratch/wave4-refutations-20260920.md`. Plus
   pre-existing refutations S5, S6, W7. The likely-FP cluster is fully cleared.
4. **V5–V7 rejected-stage CAUTION**: their `rejected` stage comes from a
   BLOCKED-guard replay ("no demonstrated effect"), not a refutation — they are
   source-confirmed but unrunnable offline (cargo cache gaps, no PostgreSQL).
   Re-running `verify` with a working server flips the stage. If submitted at
   all, they go as source-analysis findings with the harness-blocked caveat
   stated, or wait for a provisioned environment.
5. **Housekeeping done**: review docs archived to `scratch/review-docs-archive/`
   (targets clean), `add_candidates.sh` retired, restore-note CLOSED, AGENTS.md
   ledger paragraph current.
