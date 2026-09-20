# Wave 4 dispositions — likely-FP cluster (P5, W5b, W6, P4, S2, V4) — 2026-09-20

Formal validation of the six claims flagged in `claimed-vulnerabilities.md`
cross-cutting flag 3. Outcome: **five rejected/refuted, one real and now
verified** (S2). Every disposition is first-class data: two are differential-
gate rejections recorded in the ledger (`stage=rejected`), one is a
differential-gate *verification* (`stage=verified`), three are code-trace
refutations documented here (no honest offline replay exists for them; they
await an LLM-endpoint `triage` run to set verdict=fp in the ledger).

## Summary

| Claim | Ledger | Disposition | Mechanism |
|---|---|---|---|
| W5b TypeError on tokenless user | #136 (new; parked #117) | **REJECTED** | differential gate 0/3 |
| P4 control-socket perms/peer-cred | #128 | **REJECTED** | differential gate 0/2 |
| S2 slow-client worker exhaustion | #112 | **REAL — VERIFIED** | differential gate 3/3 |
| P5 hardcoded dump key | #129 | refuted (doc) | code+man-page trace |
| W6 removeChild(s) ReferenceError | #125 | refuted (doc) | code trace, no boundary |
| V4 AppleScript injection RCE | #115 | refuted (doc) | trust-model trace |

## W5b — rejected (#136, gate 0/3)

Claim: `handleUserCountry.js:5` throws TypeError on `general_token.length`
for tokenless users, so the EU rawlog-pause flow never engages.

- Fix `c09e0be` "fix(WTM-1280): conditionally reading general_token" changed
  `if (general_token.length === 0)` → `if (!general_token) return ""` and IS
  an ancestor of HEAD `64e9989c65` (`git merge-base --is-ancestor` → 0).
- Consumer `onInstalledBackgroundEventListener.js:36-42` now receives `""`
  (falsy; `.length === 0`) instead of a rejection.
- Harness: `scratch/wtm-verify/c117-{vuln,control}.mjs` loads the REAL
  handler module via the resolve hook (synthetic chrome storage, feathers
  stub, canary token only). Oracle prints only the claimed effect.
  Both runs: `CLAIM_EFFECT=none`, rc 0 → identical → `verify 136 --repeat 3`
  recorded 0/3 differential, `stage=rejected`.
- The parked row's own author had anticipated this FP — confirmed.

## P4 — rejected (#128, gate 0/2)

Claim: control socket has no peer-credential check and perms left to umask
(`server/mod.rs:444`), so other local users can drive the daemon.

- `cache_path()` (`main.rs:74-105`) create-if-missing + **chmod 0700 on BOTH
  components** (runtime dir and `pizauth` leaf) and **fatals on chmod
  failure** (fails closed; also defeats path-squatting — a squatted dir
  can't be chmod'd by us → startup aborts). The socket sits inside both.
- Harness `scratch/p4_server.rs` (rustc, std-only) replicates `cache_path()`
  + `sock_path()` + the plain `UnixListener::bind` verbatim; run under
  **umask 000**. Measured: `runtime_dir_mode=700 cache_dir_mode=700
  socket_mode=777` — the socket file itself IS umask-dependent (the claim's
  true half) but others-class lacks search on the 0700 parents, so a
  cross-UID connect cannot path-resolve (POSIX path-resolution guarantee;
  no root in the sandbox for a live setuid connect, so the kernel's own
  mode bits are the oracle — `scratch/p4_connect.py`).
- Sensitivity check (not part of the pair): counterfactual layout without
  the 0700 enforcement (`umaskonly` mode → 777/777/777) prints
  `CLAIM_EFFECT=unauthorized_access` — the oracle is not rigged.
- Verify pair (`scratch/p4-{vuln,control}.sh`): vuln = attack oracle on the
  real layout (umask 000) → `none`; control = inert baseline → `none`;
  0/2 differential, `stage=rejected`.
- Residual true fact: `request()` (`mod.rs:87-104`) really does no
  SO_PEERCRED check — but only same-uid (or root) can reach the socket, and
  same-uid is pizauth's documented single-user threat model (`pizauth show`
  prints access tokens to stdout for that same user by design).

## S2 — REAL, verified (#112, gate 3/3)

Claim: per-read timeout only (`httpserver.rs:156-158`, NET_TIMEOUT=10s), no
overall request deadline → a few unauthenticated slow clients occupy all
HTTP workers indefinitely.

Code facts at HEAD `6d86d72e75`:
- `:24` MAX_SIMULTANEOUS_CONNECTIONS = 16; `:138-143` accept loop parks
  (100ms sleep) while `active > 16`; each accepted conn gets a thread
  (`:147-150`) running `request()` → `parse_get()`.
- `parse_get` (`:326-383`) has no aggregate deadline; `req_time` (`:167`) is
  used only for queue ordering. Each `read_line` survives as long as ANY
  byte arrives within each 10s window.
- Signature/event/owner checks happen AFTER the full header+body read →
  the attack is fully pre-auth.

Live replay (offline, loopback only; binary built from the pinned snapshot
with `cargo build --offline --release`, toolchain 1.96.0, artifacts in
`/tmp/opencode/snare-target`):
- `scratch/s2_slowloris.py`: 18 connections each send a complete request
  line then ONE byte per 2s (well under 10s), never completing the first
  header line. Memory per conn ≈ bytes dribbled — this isolates S2
  (worker occupancy) from S1 (unbounded header memory).
- `scratch/s2_legit.py`: one well-formed unsigned `ping` delivery (repos
  with no secret accept unsigned by design, `:295`).
- Control: `HTTP/1.1 200 OK` in 0.01s, `CLAIM_EFFECT=none`.
- Vuln: legit delivery **times out** (6.01s client timeout),
  `CLAIM_EFFECT=worker_exhaustion_denial`; whole replay ~10s, deterministic
  sha across repeats.
- `verify 112` → 1/1 then `--repeat 2` → 2/2; **3/3 total, stage=verified**.
  First exploit-replay verification in the ledger (#127 was a presence
  check).
- Note the off-by-design detail: `active.fetch_add(1) > 16` lets a 17th
  connection through, so the attacker needs ≥17 parked connections, not 16.
- The variant lane's "bounded by design" doubt conflated memory bounding
  (true: 16-17 threads max) with availability (false: that IS the DoS —
  18 sockets ≈ 2 bytes/sec total starve the daemon). Rejecting the doubt.

## P5 — refuted, documented tradeoff (#129 stays candidate pending triage)

Claim: token dump "encryption" uses a hardcoded published ChaCha20 key
(`state.rs:39`), CWE-321.

- `state.rs:35-36`: the code's own comment scopes it — "We **lightly
  encrypt** the dump output to make it at least resistant to simple
  string-based grepping."
- Man page `pizauth.1:38-42`: "it is **trivial for an attacker to recover**
  access and refresh tokens from it: it is strongly recommended that you
  use external encryption on the output".
- No honest differential exists: the mechanism (public-key "decryption") is
  real but the project explicitly documents it as non-security
  obfuscation with external encryption as the actual boundary — the same
  refutation class as parked S6 (documented tradeoff). A rigged
  vuln/control pair would only launder a judgment into a fake measurement,
  so this is recorded here instead of through `verify`.
- The variant lane's original decline to register was correct.

## W6 — refuted, no security boundary (#125 stays candidate pending triage)

Claim: `checkScripts` references undefined `s` in `removeChild`
(`handleScriptInjection.js:15`), so a hostile page can plant duplicate
script elements and abort WTM injection (CWE-457, low).

Correction to the earlier doubt: this is **not dead code** —
`handleScriptInjection` is called at HEAD from `src/contents/index.js:25`
and `src/daemon/index.js:24`. The ReferenceError is genuinely reachable:
`existing.length > 1` → `target.removeChild(s)` throws, `injectScript` has
no try/catch around `checkScripts` (`:47`), and `handleScriptInjection`
calls `injectRequestOverload` (`:98`) unguarded → the whole handler aborts.

Why it is still not a finding:
- The only "victim" is WTM's measurement of the *hostile page itself* — no
  user-facing compromise, no data exposure, no privilege gain.
- The same evasion is available to any page without the bug: a strict
  Content-Security-Policy blocks the DOM-injected `<script src>` outright.
  The bug adds no adversary capability that CSP doesn't already grant.
- CWE-457 (unused variable) is a code-quality class; the correct venue is
  an upstream robustness patch note, not a security submission. FP-scoring
  is zero, so this never ships.

## V4 — refuted, no boundary crossed (#115 stays candidate pending triage)

Claim: agent-settable workspace name flows into `osascript -e` with only
`"` escaped (`notification.rs:157-168`); a backslash "terminates the
AppleScript string and yields arbitrary osascript code execution".

Reachability (confirmed by trace): `notify()` call sites interpolate the
workspace name into title/message — `services/container.rs:244-258`
("Workspace Complete: {name}") and `approvals/executor_approvals.rs:62-95`;
the name is settable with arbitrary bytes via MCP `update_workspace`
(`mcp/src/task_server/tools/workspaces.rs:169-208` → PUT
`/api/workspaces/{id}`, no validation, `db/src/models/workspace.rs:408-435`)
and the vibe-kanban MCP is preconfigured into every agent
(`executors/default_mcp.json`).

Refutation legs:
1. **No security boundary crossed (decisive, platform-independent).** The
   same agent principal already has *ungated arbitrary shell* on the host:
   `ScriptRequest::spawn` runs agent-settable scripts with `_approvals`
   ignored (`executors/src/actions/script.rs:41-72`; scripts settable via
   MCP `update_setup_script`/`update_cleanup_script`/`update_dev_server_script`,
   `mcp/src/task_server/tools/repos.rs:129-215`), Cursor runs `--force`
   under the default `Auto` permission policy (`executors/cursor.rs:640`,
   `model_selector.rs:53-61`), and the approval bridge exists only for
   Codex/Claude/Gemini/Qwen/Opencode
   (`local-deployment/src/container.rs:1331-1346`). Even a perfect AppleScript
   injection would grant nothing the agent doesn't already have.
2. **Sink is the fallback notifier only.** `set_global_push_notifier` is
   called only in the production Tauri branch (`tauri-app/src/main.rs:200`,
   `else` of `cfg!(debug_assertions)`); the shipped desktop app uses the
   native Tauri notifier. `osascript` is reached only by the standalone
   backend (npx CLI default browser mode) and Tauri dev builds, on macOS.
3. **RCE mechanism not demonstrable (residual, honestly unverified).**
   Quote-escaping means every attacker `"` arrives as `\"`; the classic
   inject-a-literal path is closed. A trailing/`\"` backslash CAN shift
   string boundaries (early termination — cosmetic: malformed script,
   notification silently lost), but constructing a `do shell script
   <attacker literal>` requires an unescaped quote in bare position, which
   the escaping appears to prevent. NOT empirically settled: no `osascript`
   exists on this Linux box and a hand-rolled AppleScript lexer was
   deliberately rejected as a fake-precision oracle for the differential
   gate. If this ever matters, re-test on macOS.
4. Correct disposition regardless: upstream hardening note (escape `\` too,
   or pass args out-of-band), not a vulnerability submission.

## S1 follow-up (post wave 4, same session)

Prompted by the wave-4 outcome (S2 real), S1 was measured next and is now the
second exploit-replay verification:

- **#111 VERIFIED, differential 2/2.** `scratch/s1_headerflood.py`: one
  unauthenticated loopback connection floods 192 MiB of header lines
  (`X-canary-flood: …`, ~8 KiB/line, no blank line) → snare RSS 5 → 209 MiB
  (~1.06× input) in 2.5 s, released to 5 MiB on disconnect. Control: the same
  193 MiB as well-formed 32 KiB-body requests through the 64 KiB-capped body
  path (`httpserver.rs:372-378`) → RSS flat, `CLAIM_EFFECT=none`. Same byte
  volume, bounded vs unbounded — isolates the uncapped header path
  (`parse_get` `:326-383`: no line-length or header-count cap) as the cause.
- **#116 is a dup**: its attached cmds were prose describing the S2
  measurement (16 trickling sockets + no-response observation) and never
  ran; #111 carries the canonical S1 verification.
- Memory held only while the connection is open (freed on close) — the DoS
  condition is N attackers × M MiB held open, unbounded up to OOM.
- snare now has two verified pre-auth DoS rows with independent vectors:
  S1 memory (#111), S2 worker occupancy (#112).



Rows #131–#135 were registered by a concurrent lane during this session
(15:07–15:11): W5a → #131 (verified), W8 → #132 (verified), V5/V6/V7 →
#133–#135 (candidates). No interaction with the wave-4 rows.

## Housekeeping performed

- `scratch/wtm-verify/c117-{vuln,control}.mjs` rewritten to a claim-only
  oracle (`CLAIM_EFFECT=...`) so the differential measures the claim, not
  fixture noise.
- Build artifacts kept out of the read-only snapshots
  (`/tmp/opencode/snare-target`); no files were left inside any target
  repo; no commits made.
