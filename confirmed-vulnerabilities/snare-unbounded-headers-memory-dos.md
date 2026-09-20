# Second-opinion report: snare unbounded pre-auth header memory (ledger #111 / claim S1)

- Snapshot tested: `6d86d72e75a622d53149612753a7a4e55a29abb7` (`git rev-parse HEAD`), snare v0.4.13.
- All testing on 127.0.0.1 only; synthetic config, no secrets; binary rebuilt offline from the read-only source (`scratch/target-snare`, sha256 `d381f135…`, provenance in `scratch/verify/snare-S1-second-opinion/evidence/build-provenance.txt`).
- This is an independent confirmation: new harness (`scratch/verify/snare-S1-second-opinion/`), new build, gate re-run 3/3.

## Verdict

**CONFIRMED** (confidence 0.95). A single unauthenticated remote connection can grow
the snare daemon's resident memory without bound — measured 1.06× the bytes sent — by
streaming non-terminating HTTP header lines. This is **distinct from S2/#112** (accept-loop
slot starvation): during the flood the daemon still answered 6/6 fresh probe connections,
because only 1 of the 16 worker slots is in use.

The single piece of evidence that would most change my mind: a deployment behind a
request-buffering reverse proxy that caps header size before forwarding (see
"Adversarial self-check") — the mechanism requires the client's bytes to reach snare's
listener directly.

## Root cause

`src/httpserver.rs`, `parse_get` (`:326-383`), which runs **before any authentication**
(the HMAC check is at `:277+`, after parsing completes):

- `:329` — request line read with unbounded `read_line`.
- `:340-361` — header loop: every line is read with unbounded `read_line` and pushed into
  `headers: Vec<String>` (or appended to the previous entry for obs-fold continuations,
  `:354`). The loop terminates **only** on a blank line (or read error); there is no
  per-line length cap, no header count cap, no total header byte cap.
- `:29`, `:372-378` — the only size cap, `MAX_HTTP_BODY_SIZE = 64 KiB`, applies to the
  body and is only checked **after** the header loop completes.
- `:26`, `:157-158` — `NET_TIMEOUT = 10 s` is a per-read syscall timeout; a client that
  sends steadily never trips it, so nothing bounds accumulation over time either.
- No rlimit or allocator cap is installed anywhere in `main.rs`.

Net effect: daemon heap grows ~1:1 with attacker input while the connection stays open;
memory is returned when the connection closes (`Vec<String>` dropped), so the attacker
sustains the flood to hold memory and can drive RSS to the machine's OOM threshold.

## Reproduction (verbatim)

```sh
git rev-parse HEAD        # 6d86d72e75a622d53149612753a7a4e55a29abb7
cd snare
RUSTUP_TOOLCHAIN=1.96.0 CARGO_TARGET_DIR=../scratch/target-snare cargo build --release --offline

# config: scratch/verify/snare-S1-second-opinion/snare.conf
#   listen = "127.0.0.1:18013";  github { match ".*" { } }

sh ../scratch/verify/snare-S1-second-opinion/vuln.sh     # one connection, 192 MiB of headers
sh ../scratch/verify/snare-S1-second-opinion/control.sh  # same volume via capped 32 KiB bodies
python3 funnel.py verify 111 --repeat 3 \
    --vuln   'sh ../scratch/verify/snare-S1-second-opinion/vuln.sh' \
    --control 'sh ../scratch/verify/snare-S1-second-opinion/control.sh'
```

Harness: `scratch/verify/snare-S1-second-opinion/measure.py` — samples daemon `VmRSS`
from `/proc/<pid>/status` every 50 ms; vuln mode floods header lines (`X-Canary-Flood: …`,
~8 KiB each, never a blank line) on ONE connection and simultaneously probes service
with trivial requests on fresh connections; control mode delivers the same total bytes
as well-formed ping POSTs with 32 KiB bodies (terminated headers, 64 KiB-capped body
path). Everything bounded: fixed 192 MiB dose, socket timeouts, 90 s watchdog.

## Measurements

| Run (this lane, own build) | RSS start | RSS peak | RSS after close | Bytes sent | Δ RSS | Δ/input | Probes answered during flood |
|---|---|---|---|---|---|---|---|
| vuln (dry run)   | 5 MiB | 209 MiB | 5 MiB | 192 MiB | 204 MiB | 1.06 | 6/6 |
| control (dry run)| 5 MiB | 5 MiB   | 5 MiB | 193 MiB | 0 MiB   | 0.00 | n/a  |
| vuln (gate ×3)   | 5 MiB | 209 MiB | 5 MiB | 192 MiB | 204 MiB | 1.06 | 6/6 each |
| control (gate ×3)| 5 MiB | 5 MiB   | 5 MiB | 193 MiB | 0 MiB   | 0.00 | n/a  |

Gate: **3/3 differential YES** (`evidence/gate-verify-111.txt`). Prior lane's stored runs
(2/2, RSS 5→208/210 MiB) reproduced within 1 MiB. The ~1.06× ratio matches `Vec<String>`
storage of ~8 KiB lines plus allocator overhead — the growth is heap in the daemon
process, not kernel socket buffers (not counted in `VmRSS`) and not the 8 KiB `BufReader`.

## Adversarial self-check

- **Is this just S2/#112 again?** No. S2 needs 17 slow connections to wedge the accept
  loop and measures *probe failure*; S1 uses ONE fast connection and measures *RSS*.
  6/6 probes answered during the flood show the accept loop is free while memory climbs.
  The two compose (dribbling the flood also parks a slot) but the memory effect stands
  alone.
- **Is byte volume itself the cause?** No — the control pushes the same 193 MiB through
  the capped body path and RSS stays flat at 5 MiB. Only the uncapped header path grows.
- **Self-heal?** Yes on disconnect: RSS returns to 5 MiB within ~0.5 s of close. The DoS
  window is exactly as long as the attacker sustains the flood; the OOM-kill risk exists
  while it is sustained.
- **Config option that neutralizes it?** None. `MAX_HTTP_BODY_SIZE` (compile-time,
  `:29`) does not cover headers; `snare.conf.5` exposes no header limits. The `timeout`
  option (`snare.conf.5:224`) bounds job commands, not the HTTP read path.
- **Deployment caveat:** the README's reverse-proxy recommendation (nginx et al.) would
  buffer/cap request headers before forwarding and blunt this; but snare's own example
  config binds `0.0.0.0:8011` directly (`snare.conf.example:6`), so as shipped it is
  exposed.
- **Harness honesty:** the oracle prints measured numbers and a threshold rule
  (Δ ≥ 50 % of dose ⇒ effect); both scripts fail loudly (exit 2, `HARNESS_ERROR=…`) if
  the daemon is not up, so an asymmetric crash cannot fake a differential.

## Suggested remedy (informational)

Cap the header section in `parse_get`: reject once accumulated header bytes exceed a
constant (e.g. 64 KiB, matching the body cap) and/or cap per-line length and header
count; optionally enforce a whole-request deadline (which is also the S2 remedy).
Checking `Content-Length` before reading headers does not help — the loop must be
bounded itself.

## Measured vs inferred

Measured: RSS 5→209 MiB (204 MiB Δ, 1.06× input) on one connection, 192 MiB in ~1.7 s;
flat control at identical volume; memory release on close; service continuity during the
flood; 3/3 gate. Inferred (not run, deliberately bounded dose): OOM kill / allocator
failure at host-RAM scale, behaviour behind real proxies, non-loopback RTTs.
