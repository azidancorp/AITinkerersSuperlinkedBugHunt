# Second-opinion report: availability of snare's webhook HTTP server

- Snapshot tested: `6d86d72e75a622d53149612753a7a4e55a29abb7` (`git rev-parse HEAD`)
- All testing on 127.0.0.1 only; synthetic config/credentials; build and harness under /tmp.

## Verdict

**CONFIRMED** (confidence 0.95). An unauthenticated remote client can make a running
snare daemon stop serving webhook deliveries for as long as it chooses, using 17
connections that each send ~1 byte per 3 seconds (~6 bytes/s total). No credentials,
no valid webhook, no bandwidth.

The single piece of evidence that would most change my mind: a production deployment
behind a request-buffering reverse proxy (see "Adversarial self-check") — the
mechanism depends on the client talking directly to snare's listener.

## Root cause

`src/httpserver.rs` runs one thread per accepted connection and caps them:

- `src/httpserver.rs:24` — `static MAX_SIMULTANEOUS_CONNECTIONS: usize = 16;` (compile-time constant; no config option exists)
- `src/httpserver.rs:138-143` — the accept loop *blocks* while active threads exceed the cap, so once 17 connections are held, no further connections are ever accepted; legitimate requests strand in the kernel backlog and time out
- `src/httpserver.rs:26`, `:157-158` — `NET_TIMEOUT = 10s`, applied via `set_read_timeout`/`set_write_timeout`. This bounds each individual `read()`/`write()` syscall, **not** the total time a request may take: every byte received resets the 10 s window.
- `parse_get` (`src/httpserver.rs:329,343,380`) reads the request line, loops `read_line` over headers, then `read_exact` over the body. As long as a byte arrives inside each 10 s window these calls never error, so the handler thread never completes and never releases its slot. `req_time` (`:167`) is recorded but only used for queue bookkeeping (`:310`); it is never enforced as a deadline.

The timeout is the only safeguard against slow clients, and it is defeated by
dribbling one byte every 3 s (< 10 s) inside an unfinished header. Each held
connection costs the attacker ~0.33 bytes/s and occupies one of the 16 worker
slots indefinitely; the 17th connection wedges the accept loop itself. Note that
authentication (the HMAC secret check) happens only after a complete request is
parsed, so holding connections open pre-auth requires no credentials at all.

Measured threshold: exactly **17 held connections** (16 dribblers left all probes
succeeding; 17 caused total denial).

## Reproduction (verbatim)

```sh
git rev-parse HEAD   # 6d86d72e75a622d53149612753a7a4e55a29abb7
RUSTUP_TOOLCHAIN=1.96.0 CARGO_TARGET_DIR=/tmp/snare-target cargo build --offline --release

cat > /tmp/snare.conf <<'EOF'
listen = "127.0.0.1:9111";
github {
  match ".*" {
    cmd = "/bin/echo %e %o %r";
  }
}
EOF
/tmp/snare-target/release/snare -c /tmp/snare.conf &
```

Attack (python3): open N connections, send `POST / HTTP/1.1\r\nX-Slow: `, then one
byte every 3 s, never terminating the headers. Harness used:
`/tmp/snare-test/final_check.py` (attack + probe + recovery measurement) and
`/tmp/snare-test/sweep2.py` (connection-count sweep). Probe = well-formed unauthenticated
`POST` with `X-GitHub-Event: ping` and a small JSON body.

## Measurements

Probe = ping webhook request, 3 s timeout, one probe per second during a 45 s
sustained attack window.

| Scenario                        | Probes ok | Probes failed | ok latency | Recovery after attack stops |
|---------------------------------|-----------|---------------|------------|------------------------------|
| Baseline (no attack), 30 probes | 30        | 0             | avg 0.3 ms | —                            |
| 16 dribbling connections        | 45        | 0             | avg 0.5 ms | instant                      |
| 17 dribbling connections        | 0         | 12            | —          | ~3 s                         |
| 20 dribbling connections        | 0         | 12            | —          | ~3 s                         |
| 17 idle connections (no dribble)| 37        | 2             | avg 0.5 ms | instant                      |

Independent sweep (`/tmp/snare-test/sweep2.py`, 8 s windows): N=15,16 all probes ok;
N=17,18,20 all probes timed out. Failures are TCP timeouts — the daemon stays alive
and `LISTEN`ing but never accepts/answers — not connection-refused.

Attack cost: ~1 byte / 3 s per connection (could be stretched to ~1 byte / 9 s);
17 connections ≈ 5.7 bytes/s total. One parked thread per connection server-side;
no large memory or CPU cost to the attacker.

## Adversarial self-check

- **Self-heal**: yes. When the attacker stops, normal traffic recovers in ~3 s.
  The daemon never crashed in any run; availability loss lasts exactly as long as
  the attack is sustained.
- **Is the dribble essential?** Yes. 17 *idle* connections (no bytes) barely degrade
  service (37 ok / 2 fail): the 10 s `NET_TIMEOUT` reaps them. The low-bandwidth
  dribble is what converts a momentary slowdown into a sustained outage.
- **Config option that neutralizes it?** None. `MAX_SIMULTANEOUS_CONNECTIONS` and
  `NET_TIMEOUT` are compile-time constants; `snare.conf.5` exposes no connection or
  HTTP timeout limits. (The `timeout` option at `snare.conf.5:224` is the job-command
  runtime limit — SIGTERM after N seconds — unrelated to the HTTP path.)
- **Documented deployment pattern**: the README ("HTTPS/TLS" section) recommends a
  reverse proxy such as nginx or relayd for encryption. A request-buffering proxy
  terminates slow-dribble clients itself and only forwards complete requests, which
  incidentally neutralizes this mechanism. But snare has no protection of its own,
  and its own example config binds `0.0.0.0:8011` directly (`snare.conf.example:6`),
  so as shipped and as documented it is exposed.

## Suggested remedy (informational)

Enforce a whole-request wall-clock deadline (e.g. reject once `req_time.elapsed()`
exceeds a few seconds) inside `parse_get`/the header loop, and/or cap per-connection
header count/size and total read time independently of the per-syscall `NET_TIMEOUT`.
Raising `MAX_SIMULTANEOUS_CONNECTIONS` alone only raises the (still cheap) threshold.

## Other availability issues found

None beyond the claim. `MAX_HTTP_BODY_SIZE = 64 KiB` (`src/httpserver.rs:29`) bounds
per-request memory; ping handling and queueing behaved normally throughout.

## Measured vs inferred

Measured: threshold of 17, total denial while ≥17 dribblers are held, ~3 s recovery,
idle-connection self-heal, baseline/attack latencies. Inferred (not tested): an
idle-connection variant where the attacker reconnects every <10 s should also
sustain denial; behaviour of specific proxies in front of snare; behaviour on
non-loopback networks with real RTTs.
