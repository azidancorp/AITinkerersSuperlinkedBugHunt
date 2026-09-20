# snare variant lane — seed reviews & rejections (2026-09-20)

Lane: manual variant analysis over all 22 `fix` + 17 `churn-A` snare seeds
(HEAD 6d86d72). Outcome: **0 candidates registered** — every candidate-shaped
idea failed the concrete source→sink / attacker-controlled bar. Full audit
trail below; rejections are first-class data for the operator's later stages.

## Method note

Read all of `src/` at HEAD (httpserver.rs, jobrunner.rs, config.rs, config.l,
queue.rs, main.rs, config_ast.rs — 2,279 LOC total) plus
`tests/auth.rs`, `snare.conf.5`, `snare.conf.example`, then reviewed each fix
seed with `git diff <sha>^1 <sha>`.

## Ideas probed at HEAD and rejected (with reasons)

1. **Case-sensitive `match` regex vs case-insensitive GitHub owner/repo
   names** (config.rs `repoconfig`:352; httpserver.rs:277-296).
   Attacker flips case of body-claimed `repository.owner.login` so a
   case-specific secret block misses and a secretless catch-all `cmd` runs
   unsigned. REJECTED after differential trace: the case flip never makes a
   secret-protected `cmd` reachable unsigned — it only selects a *different,
   already-secretless* match block, which the attacker can reach unsigned
   with any owner claim anyway (no case trick needed). No privilege delta ⇒
   FP under zero-FP scoring. Documented posture: snare.conf.5 "we highly
   recommend setting [a secret] in all cases". A scratch replay harness was
   built, then deleted with the rejection.
2. **`verify_str` byte-wise scan panics on multibyte UTF-8 in `cmd`/`errorcmd`**
   (config.rs:320-337; `i += 1` in the else branch lands mid-char ⇒
   `s[i..]` slice panics). Config-load DoS only — config is trusted local
   input, not attacker-controlled. Robustness, not a finding.
3. **`unescape_str` release-mode silent backslash drop** — `config.l` STRING
   regex `"(?:\\\\|\\"|[^"])*"` admits lone `\x` via `[^"]`; the
   `debug_assert!`s vanish in release so `\q` silently becomes `q`
   (config.rs:386-410). Trusted-config mangling only.
4. **Unbounded queue growth for unsigned requests when no secret is
   configured** (queue.rs `push_back`, httpserver.rs `(None, None) => ()`) —
   documented tradeoff (man page recommends secrets "in all cases"); 64 KiB
   body cap and 16-thread cap bound the rest. Hardening gap.
5. **HTTP request smuggling surface in hand-rolled `parse_get`**
   (dup Content-Length last-wins, Transfer-Encoding ignored) — dead class:
   snare serves exactly one request per connection (no keep-alive; read side
   shut down after body), so desynced bytes are never reinterpreted.
6. **Log injection via `x-github-event` / Content-Type into warn strings** —
   header values cannot contain newlines (read_line framing + trim_end), and
   syslog is called with a fixed `"%s"` format. Not injectable.
7. **Slowloris thread parking (10 s read timeout)** — bounded by
   MAX_SIMULTANEOUS_CONNECTIONS=16 + accept-loop throttle. By design.
8. **Shell-safety of `%e/%o/%r` substitution into `sh -c`** (jobrunner.rs
   `cmd_replace`) — VERIFIED SAFE: event `[a-z_]`, owner `[A-Za-z0-9-]` (no
   lead/trail/double hyphen), repo `[A-Za-z0-9-_.]` minus `.`/`..`; all
   validated in httpserver.rs before queueing; `%j/%s/%x/%?` are
   tempfile paths / enum+int exit codes. Example conf's "shell-safe"
   guarantee holds at HEAD.
9. **Privilege-drop order, temp-file perms, HMAC path** — bind happens after
   `setresuid` (safe order); tempfile crate ⇒ 0600 JSON/stderrout; HMAC-SHA256
   over raw body incl. `payload=` prefix with constant-time verify. All sound.

## Seed-by-seed dispositions (snare)

Fix pool: `0bfee4d8` queue tests (test-only) · `83546381` #126 ports
(test infra + SNARE_DEBUG_PORT_PATH) · `f7266ee4` #125 clippy · `3d733e2c`
#118 buildbot/deny.toml · `5d1189bb` #111 clippy (`mac.update(&pl)`) ·
`285895180e` #96 comment fix · `9e3e5595` #86 Cargo.lock · `26740da7` #79
config.rs renames (2-line) · `dbbbd371` #78 crypto_mac trait rename ·
`39abfd10` #73 Cargo.lock · `749994aa` #72 README · `0fa1ad53` #68 clippy
(`chars().next`) · `d50355c7` #61 docs · `32e3886e` #53 example-conf +
test · `25a8a1c9`/`bec4ffd6`/`d62a869d`/`df1d56ea` #51/#50/#49/#47 style,
clippy, reposdir error path · `d042cfa3` #40 clippy · `57b176e1` #23 README
· `ae6895f9` #6 markdown · `17628fdb6` #3 markup.
Churn-A pool: `7df5404e` string-escaping fix — present and correct at HEAD
(`i += c2.len_utf8()`); sibling escape holes probed (see #2/#3 above, both
trusted-config) · `1263ecec` hand-rolled HTTP server introduction — parser
audited in full (see #5/#6) · remaining churn-A (`9daaafa5`, `06a7e8ff`,
`e318c6f7`, `f2b23e30`, `bd4aa324`, `a4f06645`, `29f9c026`, `a202e70a`,
`2bcbc2c9`, `e3bf4a6e`, `6b8d1080`, `726b7159`, `cc418021`, `4fd4e119`) —
clippy/docs/lockfile/markup, no security class.

## Conclusion

snare's real bug history (escaping, string handling) is fixed at HEAD and its
auth path is tight. Zero registrations is the honest yield; candidate flow for
snare should come from other sources (fuzzing the HTTP parser / config lexer
would be the natural next lane).

## Addendum (post-lane, 14:00)

A concurrent lane registered four snare candidates as `--source manual`
(#111 unbounded header memory, #112 per-read timeout worker exhaustion, #113
job-timeout descendants blocking job slots, #114 stale Unix socket blocking
restart). Correction to this file's item 7: I bounded the slowloris analysis
to *threads* (16-cap) but missed that `parse_get`'s header loop
(httpserver.rs:340-361) has **no byte/count cap** — only the Content-Length
body is capped at 64 KiB — so #111 is confirmed real by the same trace. #113
is also consistent with the code: job completion requires stderr_hup &&
stdout_hup (jobrunner.rs:221-225) and SIGTERM goes only to the direct child,
so pipe-inheriting grandchildren pin the job slot. Rejection 7 is withdrawn;
rejections 1-6, 8-9 stand. Operator's triage/verify gates own severity calls
(#114 in particular looks availability-only, not "high").
