# Second-opinion report: vibe-kanban origin validation bypass (DNS rebinding)

- Snapshot tested: `d5cbb5380fa0b32e98ef9b8d987f63decce4be3a` (`git rev-parse HEAD`), ledger candidate **#106** (claim V2)
- All testing offline on 127.0.0.1 only; synthetic headers; harness in `scratch/verify/vibe-kanban-V2/` (kept, not /tmp)
- Gate status: **differential 3/3 YES** (`funnel.py verify 106 --repeat 3`), first verified vibe-kanban row

## Verdict

**CONFIRMED** (confidence 0.9). The sole auth-style gate on vibe-kanban's
unauthenticated local API — `validate_origin` — accepts three attacker-
controllable header shapes it must not: **no Origin header at all**, **Origin ==
Host** (Host is client-supplied), and **`x-vk-relayed: 1`** (skips the check
entirely). Under DNS rebinding the first two shapes give a web page full read/write
access to the local API, whose routes include arbitrary directory listing, config
file overwrite, the cloud access token endpoint, a PTY websocket, and workspace
creation that spawns agent executors with attacker-chosen `executor_config` and
`prompt`.

Confidence is 0.9 rather than higher because the bypass was replayed at the
middleware layer with the real `origin.rs` byte-identical (the full server cannot
be built offline — see "Reproduction"), and the downstream impact chain is
source-confirmed, not runtime-demonstrated. The single piece of evidence that
would most change my mind: an end-to-end browser rebinding demo against a running
server — which would only *strengthen* the claim, not weaken it; there is no
plausible mechanism by which the middleware behaves differently inside the full
binary, since the harness uses the identical layer wiring as `routes/mod.rs:74-76`.

## Root cause

`crates/server/src/middleware/origin.rs` is the only auth-style middleware applied
to `/api` (`crates/server/src/routes/mod.rs:70-78`: `ValidateRequestHeaderLayer::
custom(validate_origin)` on `api_routes`; the only other layer is error logging;
no handler takes an auth extractor). Three flaws:

1. **`origin.rs:48-50`** — no `Origin` header → `return Ok(())`. Browsers omit
   `Origin` on same-origin GET fetches and on top-level GET navigations, so a
   rebound page reading the API never trips the check. The repo's own unit test
   `no_origin_header_allows_request` (`origin.rs:176-179`) codifies this as
   intended ("fine for curl" per the review history) — which is exactly what
   rebinding exploits.
2. **`origin.rs:58-61` + `:113-118`** (and the second equivalence path `:74-79`) —
   an `Origin` that merely equals the client-supplied `Host` header is treated as
   same-origin. Under rebinding both headers carry the attacker's domain, so the
   equality is attacker-controlled. This shape covers same-origin POST/PUT and
   websocket handshakes after same-port rebinding.
3. **`origin.rs:44-46` + `:99-104`** — `x-vk-relayed: 1` (constant at
   `crates/relay-client/src/lib.rs:29`) returns `Ok(())` unconditionally: the gate
   trusts a client-controlled header for an auth decision.

Supporting facts verified at HEAD:

- Server binds loopback only by default (`crates/server/src/main.rs:78`:
  `HOST` defaults to `127.0.0.1`; `startup.rs:100` binds `localhost:0`) — origin
  validation *is* the security boundary for this local API.
- Impact routes (no auth extractors): `GET /api/filesystem/directory?path=`
  (`routes/filesystem.rs:19-39`, arbitrary path), `PUT /api/config`
  (`routes/config.rs:46` → `save_config_to_file`, disk write; `PUT /api/profiles`
  overrides executor launch configs), `GET /api/auth/token` (`routes/oauth.rs:90`,
  returns the current cloud access token), `GET /api/terminal/ws`
  (`routes/terminal.rs:178-180`; the handler at `:52-70` requires an
  **existing** `workspace_id` with a `container_ref` — an attacker first
  creates one via `POST /api/workspaces/start`, so the PTY is a second-step
  effect of the same bypass), `POST /api/workspaces/start`
  (`routes/workspaces/mod.rs:49` + `create.rs:212-223`: `executor_config` and
  `prompt` come straight from the request body).
- Lineage: the middleware was introduced by `346db013 "verify origin (#2139)"` and
  no later commit touches `origin.rs` — the flawed gate ships at HEAD.

## Reproduction (verbatim)

The full server cannot be built in this offline workspace. Observed first
blocker for `cargo build -p server --offline`: **`libsqlite3-sys v0.30.1`**
(its `preupdate_hook` feature enables `buildtime_bindgen`) → bindgen → needs
`libclang.so` (C API), and the system only ships `libclang-cpp.so.18`
(0 matching symbols — checked with `nm -D`). `aws-lc-sys` also lists bindgen
but is not the crate that fails first (`cargo tree -i bindgen@0.69.5 -p server`
shows libsqlite3-sys as the sole build-dep consumer). The full workspace build
fails even earlier, on `gdk-sys` (missing GTK dev libraries, pulled by the
tauri app). No feature flag avoids either without editing the repo. So the replay
follows the W5a/W8 pattern: **real HEAD source in a harness**.

Harness layout (`scratch/verify/vibe-kanban-V2/`):

- `src/main.rs` includes the real middleware **byte-identical** via
  `#[path = "/…/vibe-kanban/crates/server/src/middleware/origin.rs"] mod origin;`
  and mirrors the production wiring exactly:
  `Router::new().route("/api/probe", any(probe)).layer(ValidateRequestHeaderLayer::custom(origin::validate_origin))`
- `relay_client_shim/` carries the constant copied verbatim from
  `crates/relay-client/src/lib.rs:29` (`pub const RELAY_HEADER: &str = "x-vk-relayed";`)
- `v2-replay.py` drives raw-socket HTTP for byte-level header control

```sh
git -C vibe-kanban rev-parse HEAD        # d5cb5380fa0b32e98ef9b8d987f63decce4be3a
cd scratch/verify/vibe-kanban-V2
RUSTUP_TOOLCHAIN=nightly-2025-12-04 cargo build --offline   # ~7 s, warm cache
sh v2-vuln.sh      # attacker shapes -> expect 4/4 BYPASSED
sh v2-control.sh   # control shapes -> expect 3/3 BLOCKED
cd ../../.. && python3 funnel.py verify 106 \
  --vuln  'sh /home/…/scratch/verify/vibe-kanban-V2/v2-vuln.sh' \
  --control 'sh /home/…/scratch/verify/vibe-kanban-V2/v2-control.sh' --repeat 3
```

## Measurements

Raw-socket `GET /api/probe` against the harness; `handler_reached=1` means the
request passed the real `validate_origin` and hit the route handler.

| Shape | Headers (Host / Origin / extra) | Result |
|---|---|---|
| A no-Origin (rebinding same-origin GET / navigation) | `127.0.0.1:41783` / — | **200, handler_reached=1** |
| B Origin==Host (same-port rebinding POST/WS) | `rebind.attacker.test:41783` / `http://rebind.attacker.test:41783` | **200, handler_reached=1** |
| B2 case-variant (exercises `:74-79` OriginKey path, defeats `:59` string match) | `rebind.attacker.test:41783` / `http://REBIND.ATTACKER.TEST:41783` | **200, handler_reached=1** |
| C relay-header skip | `127.0.0.1:41783` / `http://evil.example` + `x-vk-relayed: 1` | **200, handler_reached=1** |
| K1 honest cross-origin (what the middleware was built to block) | `127.0.0.1:41783` / `http://evil.example` | 403 |
| K2 null origin | `127.0.0.1:41783` / `null` | 403 |
| K3 cross-port rebinding shape | `rebind.attacker.test:41783` / `http://rebind.attacker.test` (port 80) | 403 |

Gate: `differential vs control: 3/3 replay pair(s) YES` — deterministic stdout
hashes across all repeats (`5b11d8b4a9705a1b` vs `c7a87e3caa64aae6`), ~30 ms per
run.

## Adversarial self-check

- **Does the middleware work at all?** Yes — and that matters. K1/K2/K3 show it
  correctly blocks honest cross-origin, `null`-origin, and cross-port shapes. The
  finding is not "no CORS check"; it is that the three bypass shapes are
  attacker-controllable.
- **Is `x-vk-relayed: 1` a full-API bypass?** No — and the bug report must not
  claim that. On `relay_signed_routes`, `require_relay_request_signature`
  (`middleware/relay_request_signature.rs:30-69`) rejects unsigned relay-flagged
  requests with 401 (verified by code trace: no signature headers →
  `extract_request_signature` → `Err(Unauthorized)`). The header-only bypass is
  complete only on routes *outside* that layer: `relay_auth/*` (pairing ops) and
  the `host_relay` proxy `/api/host/{host_id}/*` (`routes/host_relay/mod.rs` wires
  only `open_remote_editor` behind signatures).
- **Is `x-vk-relayed` a web vector?** No — but not because it is a forbidden
  header name (it is **not**: the Fetch spec's forbidden list covers `Host`,
  `Origin`, `Referer`, `Proxy-*`, `Sec-*` etc., not custom `X-` headers).
  It is not a practical web vector because a cross-origin browser request
  carrying it triggers a CORS preflight and the server sends no
  `Access-Control-Allow-*` headers for `/api` (no `CorsLayer` anywhere in the
  tree); and once DNS is rebound the request is same-origin, where
  `Origin == Host` already passes — the relay header adds no browser-accessible
  capability. It remains a local-process vector (any local script can set
  arbitrary headers), which matters for the unsigned `relay_auth/*` and
  `host_relay` proxy routes. The web vectors are shape A (no-Origin GET) and
  shape B (Origin==Host, same-port). *(Corrected on independent review — see
  "Independent review" below.)*
- **Port nuance:** a cross-*port* Origin is rejected (K3). The attacker must run
  same-port rebinding (serve the attack page on the target's port number from the
  pre-rebind IP, then rebind DNS to 127.0.0.1) — a standard technique, but the
  report should state it or invite a bogus refutation.
- **Modern-browser caveat:** Chrome's Private Network Access may block
  public→localhost fetch-subresources (preflight requiring
  `Access-Control-Allow-Private-Network`, which this server never sends).
  Firefox and Safari do not implement PNA, and top-level navigations (no Origin,
  shape A) are not PNA-gated. Scope browser-exploitation claims accordingly.
- **Could the real server differ?** The harness compiles the same `origin.rs`
  bytes behind the same `tower-http` layer type; there is no second origin check
  anywhere in the tree (grep: no other consumer of `validate_origin` except
  `routes/mod.rs`, `startup.rs`, and `main.rs` — all the same wiring).
- **Config option that neutralizes it?** `VK_ALLOWED_ORIGINS`
  (`origin.rs:139-152`) only *adds* allowed origins; it never restricts Host or
  requires an Origin. No mitigation exists at HEAD.

## Suggested remediation (for the report)

Validate against the *bound* host:port (known server-side) instead of the client
Host header; require `Origin` on state-changing methods and websocket upgrades;
never treat `x-vk-relayed` as trusted input (it is for the relay hop, which has
its own signature layer — the origin middleware should simply not special-case
it). Stronger: mint a startup bearer token (a port file already exists) and
require it on all `/api` routes, making header-shape attacks irrelevant.

## Measured vs inferred

Measured: all seven header shapes above against the real middleware
(byte-identical source, production layer wiring), 3/3 differential gate, build
lineage (`346db013` introduced, untouched since). Inferred (source-confirmed, not
runtime-replayed): reachability and effect of the downstream routes (filesystem
listing, config write, token disclosure, PTY, workspace-start agent spawn) — the
full server binary could not be built offline (`libsqlite3-sys`/bindgen/
libclang, plus `gdk-sys` for the full workspace);
browser-side behaviour (which headers a real browser sends, PNA enforcement) is
standard-knowledge reasoning, not tested here.

## Independent review

An adversarial second-opinion review (2026-09-20,
`scratch/review-v2-independent-20260920.md`) re-verified the harness
(SHA-256 identity of the included `origin.rs`, verbatim shim constant,
semantically equivalent layer wiring), re-derived "origin validation is the
only `/api` gate" (including the `signed_ws.rs` `LocalPlain` fallback and the
`require_relay_request_signature` pass-through), re-ran the replay pair and
`funnel.py verify 106 --repeat 3` (3/3 YES, deterministic), and returned
**CONFIRM-WITH-EDITS**. The three corrections — the `x-vk-relayed`
forbidden-header misstatement, the `/terminal/ws` workspace precondition, and
the `libsqlite3-sys`-not-`aws-lc-sys` build blocker — were independently
re-verified against primary evidence and are applied to this report and the
worksheet.

## Artifacts

- Harness, shim, driver, scripts, full worksheet: `scratch/verify/vibe-kanban-V2/`
- Gate log: ledger #106 `verify_log` (6 runs recorded)
- Report skeleton: `.funnel/report-106.md` (fields 5/PoC and accuracy notes await human pass)
