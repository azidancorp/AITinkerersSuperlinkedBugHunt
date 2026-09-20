# Variant-analysis lane report — 2026-09-20

Mission: manual variant analysis (Big Sleep method) over the four pinned
repos, seeds from `.funnel/funnel.db`. Register-only: no verify / triage /
submit / dedup / network were run by this lane; repos stayed read-only; all
writes went through `python3 funnel.py add`. Coordinator lane: snare (me);
parallel delegated lanes: pizauth, Who-Targets-Me, vibe-kanban.

## Registrations (9 candidates, all source=variant, untriaged)

| id | target | sev/CWE | finding | evidence anchor |
|---|---|---|---|---|
| 101 | Who-Targets-Me | high / CWE-346 | Unvalidated page→extension message relay lets any same-page script reach privileged background handlers: arbitrary `general_token` overwrite, silent account deletion, forged rawlog submission, extension-reload DoS | `src/daemon/index.js:10` forwards every same-window `postMessage` verbatim to `runtime.sendMessage`; no sender/type allowlist; `onMessageEventHandler.js:55/53/75` handlers have zero auth gating |
| 102 | Who-Targets-Me | high / CWE-922 | Registration feedback writes the WTM API auth token into the host page's localStorage and re-broadcasts it via `postMessage(request, "*")` — disclosure to every script on x.com/facebook.com etc. | `src/daemon/index.js:15-16`; token is the `Authorization` credential for `submit-rawlogs` (`app.js:9-13`); nothing ever reads it back from page localStorage |
| 103 | Who-Targets-Me | med / CWE-359 | Facebook collector ships the entire graphql response line as the rawlog `advert` body; one `sponsored_data` marker anywhere → organic feed content uploaded beyond stated purpose | `platforms/facebook/handleApiResponse.js:34`; `containsSponsoredResponse` uses `$..sponsored_data` over the whole line while sibling collectors narrow payloads in-code |
| 104 | Who-Targets-Me | med / CWE-359 | YouTube advert context sends raw page URL including query params (`?search_query=` terms collected) | `platforms/youtube/getAdvertContext.js:7,13`; twitter/facebook/instagram all call `removeQueryParamsFromUrl` — YouTube omits it |
| 105 | vibe-kanban | high / CWE-79 | Reflected XSS in OAuth callback: raw `error` query param → `simple_html_response` (format! into text/html, no escaping) *before* any handoff-state check; GET navigations send no Origin header so `validate_origin` passes | `crates/server/src/routes/oauth.rs:163` + `:435` |
| 106 | vibe-kanban | high / CWE-346 | Origin validation defeated by treating `Origin == Host` as same-origin and allowing no-Origin requests; under DNS rebinding both headers are the attacker's domain → full access to the unauthenticated local API (filesystem, PTY, token, agent spawn) | `crates/server/src/middleware/origin.rs:41,45,59,113` |
| 107 | vibe-kanban | med / CWE-918 | Preview proxy forwards `/api/preview/{port}` to `http://localhost:{port}` for any client-supplied u16 port, no allowlist | `crates/preview-proxy/src/api.rs:43` |
| 108 | pizauth | low / CWE-400 | `startup_cmd` runs via `$SHELL -c` with no timeout — the one sibling the PR #73 timeouts sweep missed; systemd `Type=notify` never reports Ready while it hangs; child never killed/reaped | `src/server/mod.rs:334-358` (`child.wait()` unbounded); Ready sent only after exit (:357, branch 447-452); siblings bounded: notifier.rs:20-22, eventer.rs:15, refresher.rs:31 |
| 109 | pizauth | med / CWE-400 | OAuth callback HTTP/HTTPS listener: no read/write timeout anywhere in the tree; one detached thread per connection; `parse_get` blocks in `read_line`; size cap counted only after reads → dribbling clients park threads forever | `src/server/http_server.rs:283,302,409-414,470-486`; outbound policy is 30s (`mod.rs:44`) so the asymmetry is in-code |

All nine file:line anchors were provenance-checked against the snapshots
(cited lines read back and matched the claims). Canary replay proposals were
attached where provided (pizauth #108/#109 have turnkey loopback-only
scripts described in-ledger). None executed — verify is the operator's gate.

## Concurrent-writer observations (for the operator)

A parallel lane registered #110–#115 (13:59–14:00) after this mission's rows:
- **#110 ≈ duplicate of #105** (same OAuth-handoff XSS, different title/line
  — evaded the (target,source,file,line,title) dedupe key). Recommend
  dropping one at triage rather than burning two verify slots.
- **#111 snare "unbounded unauthenticated header memory" — confirmed real**
  by the coordinator's own trace: `parse_get` (httpserver.rs:340-361) caps
  only the Content-Length body (64 KiB), not header count/bytes; 16
  concurrent dribbling connections accumulate without bound. Original
  snare-lane rejection #7 (slowloris bounded) is withdrawn — it bounded
  *threads*, not memory.
- **#113 snare "job timeout leaves descendants alive and blocks subsequent
  jobs" — consistent with code**: job completion requires stderr_hup &&
  stdout_hup (jobrunner.rs:221-225); SIGTERM goes only to the direct child;
  pipe-inheriting grandchildren pin the job slot (Sequential queue then
  starves that repo_id).
- #114 (stale Unix socket blocks restart) looks availability-only;
  "high" severity seems inflated — triage's call.
- #115 (AppleScript injection in macOS push notification via agent-settable
  workspace name) — not reviewed by this lane.

## Rejection ledgers (first-class data)

### snare (39 seeds: 22 fix + 17 churn-A) — full audit trail in
`scratch/snare-lane-rejections-20260920.md` (incl. withdrawn-rejection
addendum). Yield 0. All fix seeds proved to be clippy/style/doc/test
commits; the two real classes (string escaping `7df5404e`, hand-rolled HTTP
server `1263ecec`) were traced at HEAD: escaping fixed; parser audited
(smuggling dead — one request per connection, no keep-alive; log injection
impossible — no newlines in header values, fixed "%s" syslog format);
`%e/%o/%r` charset validation airtight pre-`sh -c`; HMAC over raw body
constant-time; bind-after-privdrop; tempfiles 0600. Also rejected:
case-sensitive match regex (no privilege delta — secret-protected cmd is
never unsigned-reachable regardless of case); verify_str multibyte panic and
unescape_str release-mode backslash drop (trusted-config only); unbounded
queue (documented no-secret tradeoff).

### pizauth (14 seeds: 7 fix + 20 churn-A → 14 relevant)
- 5968dd83 PR#73 timeouts — fix correct at HEAD; class used productively → #108/#109.
- a0f58a74 lexer `\` escapes — fixed at HEAD: STRING regex `"(?:\\[\\"]|[^"\\])*"` (config.l:4), `unescape_str` (config.rs:655) handles exactly `\\`/`\"`; no unfixed sibling.
- 9df6e0de error notify — old frontends/ architecture gone; notifier passes `PIZAUTH_MSG`/`PIZAUTH_URL` as env vars, no tokens in messages.
- c9ea6170 XDG socket — `cache_path()` (main.rs:76-105) enforces 0700 both components, fatals on chmod failure; fails closed.
- 194f75ef PR#31 completion — completion.bash feeds only user's own config/account names into quoted `compgen -W`; config write access already implies arbitrary shell (`startup_cmd`).
- 29b6d0df drop order — eventer.rs drops ct_lock before shell_cmd at HEAD; correct.
- 05beede3 PR#97 systemd-fixups (Makefile), bb75df68 PR#56 (lifetime elision), e19948f0 PR#42 (lockfile/clippy), fd8623b4 README, f763d1d3 PR#5 macOS daemon (thin libc wrapper), d0ee11a1 frontends (architecture removed), 9fadc325 Lk/Aq (manpage markup), 326d3647 email differ (absent from snapshot) — no security class.

### Who-Targets-Me (31 fix seeds + HEAD sweeps)
- 64e9989/a332186 WTM-1341 script injection — fix present at HEAD (`!platform && !isWtmUrl()` + `"null"` checks in all three injected scripts; manifest matches platform-scoped via site-matches.json).
- c09e0bea WTM-1280 general_token — fix present (`if (!general_token) return ""`); other storage reads `?.`-guarded; write-side exposure real → became #102.
- f66f900 PR#108 rawlogs — fixed at HEAD (`user.isLoggedIn` + EU-country gating); forging-by-relay covered by #101.
- 738cbab PR#94 — `--overwrite-dest` build flag only.
- c084cb2 PR#58 windows — legacy collect.js gone at HEAD; class generalized → #103/#104.
- e6c1170 PR#8 — 2017 manifest shuffle, architecture since replaced.
- c7c6922 WTM-1196 jsonpath — instagram data-quality refactor, no injection/DoS pattern at HEAD.
- 7a26871/fe61498 PR#134/#133 — over-collection class; live instance is #103.
- Waist selector/request-field batch (44b3412, 5e499af, d44d558, 674f192, b1044b8, 2657340) + 2085a72 WTM-928 — correctness fixes; security generalization captured by #103/#104.
- 2017-era batch (4ca9fed, 7ab83a9, e520769, 14704a41, 288cef7, 7741f2d, 8c111af, 291d610, caa97b8, b5f8de8, a34b9ca, b0c0735, dcd915b) — files deleted at HEAD, no unfixed variant found.

### vibe-kanban (4 fix + ~10 hand-picked churn-A)
- 47dfcb16 shell_command_parsing — parser still shallow at HEAD (first-token-only; `;`/`&&`, `$(...)`, `perl -i`, env-prefixes evade Edit) but every consumer display-only (normalize_logs → ActionType icon); execution gating lives in agent CLIs' own permission systems → not registerable.
- 9f88c399 health refetch — React state, no trust boundary.
- 737a091/11865087 — UI/CSS noise.
- 18845c69 relay signing headers — signing.rs covers body-hash + path&query + nonce + 30s drift; fail-closed; no unfixed instance.
- 3902cc95 hardcoded shell paths — portability.
- 3a088ff6/304ee8e8 gh CLI PR creation — `Command::new` + `.arg()` (no shell); arg sources user's own repo metadata.
- 3ea8bf1e worktree paths — `repo.name` derives from validated basenames; `ScriptRequest.working_dir` join has no attacker-controlled writer.
- 48979c85 multi-device logout — audited oauth.rs instead → #105.
- 3d6fea49 keychain removal — posture, no source→sink.
- 346db013 origin middleware — the fix itself is flawed → #106.
- 3733865e export — export-only, no import sink.

## Deliberately NOT registered (uncertainty log — revisit if evidence lands)

- pizauth hardcoded dump key `CHACHA20_KEY` (state.rs:39, CWE-321-shaped) — explicitly documented as trivially recoverable in pizauth.1:38-42 with a user-facing warning; near-certain FP.
- pizauth Unix-socket `read_to_end` no timeout — same class as #109 but socket sits in 0700 dir; folded into #109 evidence.
- pizauth IdP-controlled `error` param → `PIZAUTH_MSG` — only reachable post-32-byte-state validation (+PKCE); env vars not shell-interpreted.
- vibe-kanban executor env inheritance (no env_clear; only opt-in ANTHROPIC_API_KEY removal, claude.rs:646) — by-design for CLI key passing; no crisp differential.
- vibe-kanban `CommandBuilder::extend_shell_params` join/resplit (command.rs:100) — inputs are user's own executor profiles.
- vibe-kanban relay signature in query params — logging concern; nonce map blocks replay; no demonstrated impact.
- vibe-kanban MCP `repos` setup-script registration — client is the orchestrator agent itself; not a distinct boundary crossing.
- WTM `getPlatform()` hostname suffix match (`endsWith`) — wrong in principle, unreachable at HEAD (site-matches.json constrains injection hosts).
- WTM `isWtmUrl()` substring check / `shouldBypassConsent()`+`checkScripts()` dead code (`undefined` refs) / notification-modal innerHTML (build-time constants only) / `handleYGRedirect` yougov visa (fixed host, speculative path) / `/g`-flag regex statefulness (false negatives, functional) / twitter `impressionId` as `aid=` (wrong-data not over-data).

## Stats snapshot at lane close

115 candidates | 100 triaged (25 tp / 72 fp / 3 uncertain) | 15 untriaged
(#101–#115) | 0 verified | 0 submitted.

Files: this report; `scratch/snare-lane-rejections-20260920.md` (+addendum);
ledger rows #101–#109 (this lane) / #110–#115 (parallel lane, not this
lane's writes). Deleted with rejections: the snare case-sensitivity replay
harness (no privilege delta — rationale in the snare notes file).
