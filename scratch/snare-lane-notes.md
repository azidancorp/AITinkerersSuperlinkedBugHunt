# snare lane notes (variant-analysis agent)

HEAD 6d86d72e75. Reviewed all 17 churn-A + 22 fix seeds. Most fix-pool entries are
maintenance merges (clippy, Cargo.lock, docs, licensing, test infra). Substantive
bug-class seeds: 7df5404 (unescape_str off-by-one, fixed+tested at HEAD),
f5a83b7 (config string escapes, fixed), 1263ece (hand-rolled HTTP server replacing
hyper — reviewed in full at HEAD), 26740da (errorcmd doc substitution fix, docs only),
0bfee4d (queue-kind tests — timing-based, do not assert cross-repo FIFO ordering).

## Registered
1. Pre-auth unbounded header/request-line reads in parse_get (httpserver.rs:326-382):
   read_line loops (req line :329, header loop :341-361) have no byte/count cap;
   MAX_HTTP_BODY_SIZE (:376) caps only the body. Read timeout is per-syscall (10 s),
   so trickling <1 byte/9 s holds a thread indefinitely and grows memory without
   bound. 16 such connections exhaust MAX_SIMULTANEOUS_CONNECTIONS (:24) and the
   accept loop (:138-143) sleeps forever -> daemon stops processing all webhooks.
2. Queue::pop picks the NEWEST front job across repos (queue.rs:88-92:
   `if et > qj.req_time { continue; }` skips OLDER candidates), contradicting the
   "find the oldest" comment (:83) and documented FIFO (snare.conf.5:202). Present
   since queue kinds were introduced (998931c); queue tests are single-repo/timing
   based so don't catch it. Fairness/starvation of legitimate repos' jobs under
   sustained attacker webhook load.

## Rejected (not registered)
- HMAC verify: verify_slice is constant-time; sha1 scheme rejected; raw body authed. Clean.
- cmd_replace substitutions (%e/%o/%r): charsets validated [a-z_], [a-zA-Z0-9-],
  [a-zA-Z0-9-._] -> shell-safe. verify_str/replace modifier sets match. Clean.
- Missing format! in warn/error calls (httpserver.rs:190,264,280): logs literal
  "{event_type}" etc. Cosmetic only.
- Header folding/duplicate headers: last-wins, no proxy in front -> no desync.
- Unix socket listener (074538b): default umask perms, stale socket file -> hardening
  gap, config trust model, not attacker-reachable remotely.
- Syslog via attacker-controlled Content-Type value: control-char log injection only,
  marginal.
- verify_str i+=2 vs multibyte modifier: all allowed modifiers ASCII; unknown ->
  Err. Config-time, local admin. Not a finding.
