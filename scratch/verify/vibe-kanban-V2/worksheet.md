# V2 / ledger #106 — origin-validation bypass → DNS rebinding — verification worksheet

Date: 2026-09-20 · Verifier: independent replication lane (pre-submission check)
Result: **VERIFIED — differential gate 3/3 YES** (vibe-kanban's first verified row)

## What was claimed (ledger #106)

`validate_origin` (crates/server/src/middleware/origin.rs @ HEAD d5cbb5380f) is the
only auth-style gate on the unauthenticated local API (routes/mod.rs:70-78). It:

1. returns `Ok` when no Origin header is present (origin.rs:48-50);
2. accepts `Origin == Host` where Host is client-supplied (origin.rs:58-61 quick
   string match; :74-79 OriginKey equivalence);
3. short-circuits entirely on `x-vk-relayed: 1` (origin.rs:44-46, 99-104;
   `RELAY_HEADER` const = "x-vk-relayed", relay-client/src/lib.rs:29).

Under DNS rebinding (attacker domain re-resolves to 127.0.0.1), Origin/Host are
attacker-controlled → full access to the local API.

## Source verification (all at HEAD d5cbb5380f, read-only)

| Claim | Verdict | Evidence |
|---|---|---|
| origin.rs:48-50 no-Origin → Ok | CONFIRMED | `let Some(origin) = ... else { return Ok(()) }`; repo's own test `no_origin_header_allows_request` |
| :58-61 Origin==Host string match | CONFIRMED | `origin_matches_host` :113-118; test `same_origin_allows_request` |
| :74-79 OriginKey Host equivalence | CONFIRMED | from_host_header parses client Host header |
| :99-103 `x-vk-relayed: 1` skip | CONFIRMED | is_relay_request :99-104; validate_origin :44-46 |
| /api has no other auth | CONFIRMED | routes/mod.rs:70-78 — the only layers are validate_origin + log_server_errors |
| POST /workspaces/start spawns agent w/ attacker executor_config + prompt | CONFIRMED (source) | workspaces/mod.rs:49; create.rs:212-223 destructures body fields |
| /terminal/ws PTY | CONFIRMED (source, **conditional**) | terminal.rs:178-180; handler :52-70 requires an existing workspace_id with container_ref — attacker creates one first via POST /workspaces/start |
| filesystem listing | CONFIRMED (source) | filesystem.rs:19-39, arbitrary `path` query param |
| /config write | CONFIRMED (source) | config.rs:46 `PUT /config` → save_config_to_file; also `PUT /profiles` executor overrides :49 |
| /auth/token | CONFIRMED (source) | oauth.rs:90 `GET /auth/token` returns current access token |
| server binds localhost only | CONFIRMED | main.rs:78 default HOST=127.0.0.1; startup.rs:100 `localhost:0` |

Lineage: middleware introduced by 346db013 "verify origin (#2139)"; **no later
commit touches origin.rs** — the flawed gate ships at HEAD.

## Runtime replay (the gate)

Full server binary cannot build offline. Observed first blocker for
`cargo build -p server --offline`: **libsqlite3-sys v0.30.1** (its
`preupdate_hook` feature enables `buildtime_bindgen`) → bindgen → no
`libclang.so` on the system (only `libclang-cpp.so.18`, which lacks the C API —
0 matching symbols; sole bindgen@0.69.5 consumer per `cargo tree -i`).
`aws-lc-sys` also lists bindgen but is not the first failure; the full
workspace build dies even earlier on `gdk-sys` (missing GTK dev libs, tauri).
So the replication follows the W5a/W8 pattern: **real HEAD source in a harness**.

Harness `scratch/verify/vibe-kanban-V2/`:
- `src/main.rs` includes the REAL `origin.rs` **byte-identical** via
  `#[path = ".../crates/server/src/middleware/origin.rs"] mod origin;`
- wiring mirrors routes/mod.rs:74-76 exactly:
  `Router::new().route(...).layer(ValidateRequestHeaderLayer::custom(origin::validate_origin))`
- `relay_client` shim crate carries the constant copied verbatim from
  relay-client/src/lib.rs:29 (`pub const RELAY_HEADER: &str = "x-vk-relayed";`)
- driver `v2-replay.py`: raw-socket HTTP, byte-level header control

### Matrix (2026-09-20)

Vuln shapes (all reached the handler past the real middleware):

| Shape | Headers | Result |
|---|---|---|
| A no-Origin (rebinding same-origin GET / navigation) | `Host: 127.0.0.1:41783` | 200, handler_reached=1 |
| B Origin==Host (same-port rebinding POST/WS) | `Host: rebind.attacker.test:41783`, `Origin: http://rebind.attacker.test:41783` | 200, handler_reached=1 |
| B2 OriginKey path :74-79 (case variant defeats :59) | `Origin: http://REBIND.ATTACKER.TEST:41783` | 200, handler_reached=1 |
| C relay-header skip | `Origin: http://evil.example` + `x-vk-relayed: 1` | 200, handler_reached=1 |

Control shapes (all correctly rejected):

| Shape | Headers | Result |
|---|---|---|
| K1 honest cross-origin | `Origin: http://evil.example` | 403 |
| K2 null origin | `Origin: null` | 403 |
| K3 cross-port rebinding | `Host: rebind.attacker.test:41783`, `Origin: http://rebind.attacker.test` (port 80) | 403 |

Gate: `funnel.py verify 106 --vuln sh .../v2-vuln.sh --control sh .../v2-control.sh --repeat 3`
→ **differential 3/3 YES**, stage → verified (stdout sha 5b11d8b4a9705a1b vs c7a87e3caa64aae6).

## Accuracy notes for the bug report (do not overclaim)

1. **`x-vk-relayed: 1` is NOT a full-API bypass.** It skips the origin layer, but
   `require_relay_request_signature` (relay_request_signature.rs:30-69) then
   requires a valid signature on `relay_signed_routes` → unsigned request gets
   401. The header-only bypass is complete only for routes OUTSIDE that layer:
   `relay_auth::*` (pairing ops) and `host_relay` proxy `/api/host/{host_id}/*`
   (host_relay/mod.rs wires only open_remote_editor behind signatures).
2. **`x-vk-relayed` is not a practical web vector.** NOT because it is a
   forbidden header name (it is not — custom `X-` headers are settable by JS):
   a cross-origin browser request carrying it triggers a CORS preflight and the
   server sends no `Access-Control-Allow-*` headers for `/api` (no CorsLayer in
   the tree); post-rebinding the request is same-origin where Origin==Host
   already passes, so the header adds no browser capability. It remains a
   local-process vector, relevant for the unsigned `relay_auth/*` and
   `host_relay` proxy routes. Web vectors: shape A (no-Origin GET after
   rebinding) and shape B (Origin==Host after same-port rebinding).
   *(Corrected on independent review 2026-09-20.)*
3. **Port nuance:** Origin with a different port than Host is rejected (K3).
   Same-port rebinding (serve the attack page on the target's port, then rebind)
   or no-Origin GETs are the working shapes. State this in the report.
4. **Downstream impact is source-verified, not runtime-replayed** (no offline
   server build). The origin-layer bypass itself is runtime-verified on real
   code. The impact chain (filesystem/config/token/terminal/workspace-start)
   is confirmed by reading the routes, which take no auth extractors.
5. Modern Chrome's Private Network Access may block public→localhost
   fetch-subresources (Firefox/Safari don't implement PNA; navigations carry no
   Origin and aren't PNA-gated). The server-side gate is still incorrect; just
   scope the browser-exploitation claim honestly.
6. Repo's own unit tests (origin.rs:175-243) codify the flawed behaviors
   (`no_origin_header_allows_request`, `same_origin_allows_request`) — the
   no-Origin pass is intentional design ("fine for curl"), which is exactly
   what rebinding exploits.

## Suggested fix (for the report's remediation section)

Bind-check or token instead of header-trust: reject requests whose effective
remote address is not loopback at the proxy layer won't help (rebinding hits
loopback). Recommended: require a bearer token minted at startup (port file
already exists) for all /api routes, or validate Origin against the *bound*
host:port (not the client Host header) and require Origin on state-changing
methods; never trust `x-vk-relayed` client-side (it exists for the relay hop).

## Artifacts

- harness + shim + driver + scripts: `scratch/verify/vibe-kanban-V2/`
- gate log: ledger #106 verify_log (6 runs)
- report skeleton: `.funnel/report-106.md`
