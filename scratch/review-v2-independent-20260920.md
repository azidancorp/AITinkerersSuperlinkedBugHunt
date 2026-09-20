# Independent review — vibe-kanban V2 / ledger #106

**Reviewer:** independent replication lane (adversarial review)  
**Date:** 2026-09-20  
**Scope:** `claimed-vulnerabilities.md` V2, `scratch/verify/vibe-kanban-V2/`, `confirmed-vulnerabilities/vibe-kanban-origin-bypass-dns-rebinding.md`, `.funnel/report-106.md`  
**Method:** primary-source reading + re-running the replay pair + attacking the build-blocker claim.

---

## 1. Harness faithfulness

### 1.1 `origin.rs` byte-identical inclusion

```text
sha256sum of real origin.rs:
  1ec96c1cba5be4d1c34df420ebebda08c8ea93a889e2f7500644c1b509f94a31
sha256sum of #[path]-included file in harness main.rs:
  1ec96c1cba5be4d1c34df420ebebda08c8ea93a889e2f7500644c1b509f94a31
```

`scratch/verify/vibe-kanban-V2/src/main.rs:14` points directly at the workspace's real file:

```rust
#[path = "/home/azidan/AQL/AI/AITinkerers/vibe-kanban/crates/server/src/middleware/origin.rs"]
mod origin;
```

**Verdict:** confirmed byte-identical at compile time.

### 1.2 `relay_client_shim` constant

Real `vibe-kanban/crates/relay-client/src/lib.rs:29`:

```rust
pub const RELAY_HEADER: &str = "x-vk-relayed";
```

Shim `scratch/verify/vibe-kanban-V2/relay_client_shim/src/lib.rs:11`:

```rust
pub const RELAY_HEADER: &str = "x-vk-relayed";
```

**Verdict:** confirmed verbatim.

### 1.3 Layer wiring vs. production

Production (`vibe-kanban/crates/server/src/routes/mod.rs:70-78`):

```rust
let api_routes = Router::new()
    .merge(relay_auth::router())
    .merge(host_relay::router(&deployment))
    .merge(relay_signed_routes)
    .layer(ValidateRequestHeaderLayer::custom(
        middleware::validate_origin,
    ))
    .layer(axum::middleware::from_fn(middleware::log_server_errors))
    .with_state(deployment);
```

Harness (`scratch/verify/vibe-kanban-V2/src/main.rs:32-34`):

```rust
let app = Router::new()
    .route("/api/probe", any(probe))
    .layer(ValidateRequestHeaderLayer::custom(origin::validate_origin));
```

The harness uses the same `tower-http` `ValidateRequestHeaderLayer::custom(validate_origin)` semantics. The only difference is the route set (single probe vs. full `api_routes`) and the absence of `log_server_errors`, which is a no-op observability layer.

**Verdict:** wiring is semantically equivalent for the gate being tested.

---

## 2. Completeness — are there other `/api` gates?

Independently traced `vibe-kanban/crates/server/src/routes/mod.rs` and all route files.

- The only layers applied to `api_routes` are `ValidateRequestHeaderLayer::custom(validate_origin)` and `log_server_errors`.
- `relay_signed_routes` are wrapped with `require_relay_request_signature` and `sign_relay_response`, but `require_relay_request_signature` is a **pass-through for non-relay requests** (`middleware/relay_request_signature.rs:35-37`). It only enforces a signature when `x-vk-relayed: 1` is present.
- `load_workspace_middleware` / `load_session_middleware` / `load_tag_middleware` / `load_execution_process_middleware` only load DB records by path UUID; they do **not** authenticate.
- `SignedWsUpgrade` falls back to `LocalPlain` when no `RelayRequestSignatureContext` extension is present (`middleware/signed_ws.rs:45-68`). That extension is only inserted by `require_relay_request_signature` for relay-flagged requests.
- `host_relay::router()` (`routes/host_relay/mod.rs:10-21`) places only `open_remote_editor` behind the relay-signature layer; the `/api/host/{host_id}/{*tail}` proxy routes sit outside it.
- `relay_auth::*` routes are merged into `api_routes` before `relay_signed_routes`, so they are also outside the signature layer.
- `main.rs:124-125` and `startup.rs:55-56` apply `validate_origin` to the **preview proxy** router, not to a second set of `/api` routes.

**Verdict:** on `/api`, `validate_origin` is indeed the only auth-style gate for non-relay requests.

---

## 3. Re-deriving the four accuracy notes

### 3.1 Note (a) — `x-vk-relayed: 1` on relay-signed routes → 401 backstop

`middleware/relay_request_signature.rs:30-69`:

```rust
pub async fn require_relay_request_signature(...) {
    if !is_relay_request(&request) {
        return Ok(next.run(request).await);   // pass-through for non-relay
    }
    let (request_signature, path_and_query) = extract_request_signature(&request)?;  // Err -> 401
    ...
}
```

`extract_request_signature` returns `Err(ApiError::Unauthorized)` when no signature headers are present. The relay client (`crates/relay-client/src/lib.rs:414-423`) always adds the four signature headers along with `x-vk-relayed: 1`.

**Verdict:** confirmed. Unsigned `x-vk-relayed: 1` requests to `relay_signed_routes` receive 401.

### 3.2 Note (b) — routes outside the signature layer

`routes/mod.rs:70-73`:

```rust
let api_routes = Router::new()
    .merge(relay_auth::router())          // NOT under require_relay_request_signature
    .merge(host_relay::router(&deployment)) // proxy NOT under signature layer
    .merge(relay_signed_routes)            // IS under signature layer
```

`host_relay/mod.rs:10-21` shows `open_remote_editor` is separately wrapped, but `/api/host/{host_id}/{*tail}` proxy routes (`host_relay/proxy.rs:21-23`) have no signature middleware.

**Verdict:** confirmed. `relay_auth/*` and the `host_relay` proxy are fully exposed by an origin-layer bypass.

### 3.3 Note (c) — `x-vk-relayed` is not browser-settable

**This note is technically wrong as written.** The Fetch spec's "forbidden header names" are explicitly listed and any name starting with `Proxy-` or `Sec-`. `x-vk-relayed` does **not** match any of those, so a browser `fetch()` *can* set it.

However, the **directional conclusion** is still correct for the web threat model: a cross-origin page cannot use `x-vk-relayed: 1` to bypass `validate_origin` because:

1. The request would be cross-origin (attacker domain → 127.0.0.1), triggering a CORS preflight.
2. The server sends no `Access-Control-Allow-*` headers for `/api`, so the browser blocks the request before the header matters.
3. If the attacker has already rebound DNS so the origin is same-origin, `validate_origin` already passes via `Origin == Host`, so the relay header is unnecessary.

The report should not claim the header is "forbidden" / "not browser-settable". It should say it is **not a practical web vector** because CORS blocks the cross-origin request, and same-origin rebinding already bypasses origin validation without it.

**Verdict:** conclusion is right; stated reason is inaccurate.

### 3.4 Note (d) — Origin/Host port equality is enforced

`origin.rs:113-118`:

```rust
fn origin_matches_host(origin: &str, host: &str) -> bool {
    origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .is_some_and(|rest| rest.eq_ignore_ascii_case(host))
}
```

The quick-match path compares the full origin remainder (host + `:port`) against the `Host` header. The `OriginKey` fallback (`origin.rs:74-79`) also compares parsed ports.

The replay's K3 shape (`Host: rebind.attacker.test:41783`, `Origin: http://rebind.attacker.test`) returns 403, confirming port mismatch is rejected.

**Verdict:** confirmed.

---

## 4. Replay re-run

### 4.1 Direct scripts

```text
$ cd scratch/verify/vibe-kanban-V2 && sh v2-vuln.sh && echo '---' && sh v2-control.sh
SHAPE A_NO_ORIGIN status=200 handler_reached=1 verdict=BYPASSED
SHAPE B_ORIGIN_EQ_HOST status=200 handler_reached=1 verdict=BYPASSED
SHAPE B2_ORIGIN_EQ_HOST_KEYPATH status=200 handler_reached=1 verdict=BYPASSED
SHAPE C_RELAY_HEADER_SKIP status=200 handler_reached=1 verdict=BYPASSED
VULN_EFFECT=observed (4/4 attacker-shaped requests reached the handler past validate_origin)
---
SHAPE K1_CROSS_ORIGIN status=403 handler_reached=0 verdict=BLOCKED
SHAPE K2_NULL_ORIGIN status=403 handler_reached=0 verdict=BLOCKED
SHAPE K3_CROSS_PORT_REBIND status=403 handler_reached=0 verdict=BLOCKED
CONTROL_EFFECT=blocked (3/3 control requests rejected by validate_origin with 403)
```

### 4.2 `funnel.py verify 106 --repeat 3`

```text
$ python3 funnel.py verify 106 --vuln 'sh .../v2-vuln.sh' --control 'sh .../v2-control.sh' --repeat 3
  [vuln] rc=0 32ms sha=5b11d8b4a9705a1b
  [control] rc=0 33ms sha=c7a87e3caa64aae6
  [vuln] rc=0 29ms sha=5b11d8b4a9705a1b
  [control] rc=0 33ms sha=c7a87e3caa64aae6
  [vuln] rc=0 48ms sha=5b11d8b4a9705a1b
  [control] rc=0 74ms sha=c7a87e3caa64aae6

differential vs control: 3/3 replay pair(s) YES
```

### 4.3 Differential attack

The control runs produce HTTP 403 with `handler_reached=0`. The harness's `probe` handler returns `PROBE_OK`; a 403 can only come from `ValidateRequestHeaderLayer` rejecting the request before the handler. The harness has no other rejection path.

All runs produced deterministic stdout hashes; no order dependence observed.

**Verdict:** replay reproduces the claimed differential cleanly.

---

## 5. Attacking the build-blocker claim

The worksheet states: "`aws-lc-sys` needs bindgen, bindgen needs `libclang.so` ... system only ships `libclang-cpp.so.18`".

### 5.1 System libclang check

```text
$ ldconfig -p | grep libclang
	libclang-cpp.so.18.1 (libc6,x86-64) => /lib/x86_64-linux-gnu/libclang-cpp.so.18.1

$ ls /usr/lib/llvm-*/lib/libclang.so*
(no matches)
```

The absence of `libclang.so` (C API) is confirmed.

### 5.2 Full workspace build

```text
$ cd vibe-kanban && cargo build --offline
...
error: failed to run custom build command for `gdk-sys v0.18.2`
pkg-config exited with status code 1: gdk-3.0 required but not found
```

The full workspace fails first on missing GTK development libraries (`gdk-sys`), before reaching bindgen crates.

### 5.3 Server-only build

```text
$ cd vibe-kanban && cargo build -p server --offline
...
error: failed to run custom build command for `libsqlite3-sys v0.30.1`
thread 'main' panicked at ...bindgen-0.69.5/lib.rs:622:31:
Unable to find libclang: "couldn't find any valid shared libraries matching: ['libclang.so', ...]
```

**Important:** the actual bindgen/libclang failure for `cargo build -p server` is triggered by **`libsqlite3-sys`**, not `aws-lc-sys`. The `preupdate_hook` feature of `libsqlite3-sys` enables `buildtime_bindgen`, which requires `bindgen` and therefore `libclang.so`.

`aws-lc-sys` does list `bindgen` as a build dependency, but it is not the first crate to fail in the server build.

### 5.4 Offline bypass attempts (without editing the repo)

- No system `libclang.so` is present; only `libclang-cpp.so.18.1` (C++ API).
- `sqlx` is pinned to `tls-rustls-aws-lc-rs`, and `rustls` is pinned to `aws_lc_rs` in the workspace `Cargo.toml`; switching to `ring` would require editing `Cargo.toml` (prohibited).
- Disabling `libsqlite3-sys/preupdate_hook` would also require editing `Cargo.toml`.
- `cargo build -p server --features ...` offers no feature that disables `aws-lc-rs` or `libsqlite3-sys/preupdate_hook`.

**Verdict:** the conclusion "full server unbuildable offline" is correct, but the worksheet's cited cause (`aws-lc-sys → bindgen → no libclang.so`) is imprecise. The actual blocker demonstrated is `libsqlite3-sys` (via its `preupdate_hook`/`buildtime_bindgen` feature) → bindgen → no `libclang.so`. Because building the real server is blocked, no end-to-end test against a live `/api/filesystem/directory` route was possible.

---

## 6. Impact-chain audit

| Cited downstream effect | Source finding | Blocks beyond origin? | Verdict |
|---|---|---|---|
| `GET /api/filesystem/directory?path=` | `routes/filesystem.rs:19-39` — handler takes only `State` + `Query`; no auth extractor | No | **Confirmed reachable** |
| `PUT /api/config` | `routes/config.rs:180-209` — under `relay_signed_routes`, but signature middleware pass-throughs for non-relay; writes config to disk | No | **Confirmed reachable** |
| `PUT /api/profiles` | `routes/config.rs:481-512` — same as above; overwrites executor profile config | No | **Confirmed reachable** |
| `GET /api/auth/token` | `routes/oauth.rs:282-297` — under `relay_signed_routes`, pass-through; returns cached access token | No | **Confirmed reachable** |
| `GET /api/terminal/ws` | `routes/terminal.rs:52-93` — under `relay_signed_routes`, pass-through; **requires existing `workspace_id` with `container_ref`** directory | Needs prior workspace | **Conditional** — not immediately reachable; attacker must first create/obtain a workspace id (e.g. via `POST /api/workspaces/start`) |
| `POST /api/workspaces/start` | `routes/workspaces/create.rs:212-320` — under `relay_signed_routes`, pass-through; creates workspace + calls `start_workspace` with attacker `executor_config` and `prompt` | No (requires non-empty `repos` and `prompt`) | **Confirmed reachable** |

**Important correction for the report:** the terminal PTY is not an unauthenticated one-step reach. The handler returns `ApiError::BadRequest("Attempt not found")` if the workspace UUID does not exist, and `ApiError::BadRequest("Attempt has no workspace directory")` if `container_ref` is missing. An attacker must first obtain or create a workspace (which `POST /api/workspaces/start` does). The report should state this dependency rather than presenting `/terminal/ws` as directly exploitable.

---

## 7. Write-up audit

File reviewed: `confirmed-vulnerabilities/vibe-kanban-origin-bypass-dns-rebinding.md`

### 7.1 Measured vs. inferred split

| Statement | Status | Notes |
|---|---|---|
| "real HEAD `origin.rs` compiled byte-identical" | Measured, confirmed | SHA-256 match; harness wiring equivalent |
| "4/4 attacker shapes reached the handler" | Measured, confirmed | Reproduced independently |
| "3/3 controls 403" | Measured, confirmed | Reproduced independently |
| "differential 3/3 YES" | Measured, confirmed | `funnel.py verify 106 --repeat 3` |
| "sole auth-style gate on `/api`" | Source-confirmed | No other auth layer found |
| "downstream routes take no auth extractors" | Source-confirmed | filesystem, config, profiles, auth/token, workspace start |
| "`/terminal/ws` PTY" | Source-confirmed but **overstated** | Requires existing workspace; should be qualified |
| "`x-vk-relayed` not browser-settable" | **Stated as fact, incorrect** | Not a forbidden header name; practical limitation is CORS/same-origin rebinding |
| "Chrome PNA may block public→localhost subresources" | Inferred, standard knowledge | Correctly scoped |
| "full server cannot be built offline" | Inferred, confirmed | But cited cause (`aws-lc-sys`) is wrong; actual cause is `libsqlite3-sys`/bindgen |

### 7.2 Honesty of the measured-vs-inferred section

The report's own "Measured vs inferred" section is mostly honest, but it omits two important qualifications:

1. It does not label the `/terminal/ws` PTY impact as conditional on prior workspace creation.
2. It labels the `x-vk-relayed` browser limitation as fact rather than as an inferred threat-model claim, and the stated reason (forbidden header) is wrong.

### 7.3 Specific sentences requiring correction

1. **Current (worksheet note 2 and report adversarial self-check):**
   > "`x-vk-relayed` is not browser-settable (forbidden header name)."

   **Correction:**
   > "`x-vk-relayed` is effectively not a practical web vector: a cross-origin browser request carrying it triggers a CORS preflight, and the server does not send `Access-Control-Allow-*` headers for `/api`. Same-origin rebinding already satisfies `Origin == Host`, so the relay header adds no browser-accessible capability."

2. **Current (report impact / root cause):**
   > "`/api/terminal` websocket (PTY in any workspace)"

   **Correction:**
   > "`/api/terminal/ws` provides a PTY for an *existing* workspace (`routes/terminal.rs:57-70`); an attacker must first create a workspace (e.g. via `POST /api/workspaces/start`) to obtain a valid `workspace_id` and `container_ref`."

3. **Current (report reproduction / worksheet build note):**
   > "`aws-lc-sys` needs bindgen, bindgen needs `libclang.so` ..."

   **Correction:**
   > "`cargo build -p server --offline` fails because `libsqlite3-sys` (with its `preupdate_hook`/`buildtime_bindgen` feature) requires bindgen, which requires `libclang.so` and cannot find it. `aws-lc-sys` also lists bindgen, but the observed first blocker is `libsqlite3-sys`."

---

## 8. Verdict

**CONFIRM-WITH-EDITS**

The core finding is real and reproducible: `validate_origin` is the only auth-style gate on `/api`, and it incorrectly accepts (1) missing `Origin`, (2) `Origin == Host` where `Host` is client-controlled, and (3) `x-vk-relayed: 1`. The replay pair is deterministic, the harness faithfully represents the production middleware, and no other `/api` auth gate exists.

However, the write-up and worksheet contain three factual imprecisions that must be corrected before submission:

1. The `x-vk-relayed` accuracy note misstates the browser restriction (not a forbidden header name; the real limitation is CORS/same-origin rebinding).
2. The `/api/terminal/ws` PTY impact should be qualified as requiring an existing workspace.
3. The build-blocker explanation should name `libsqlite3-sys`/`preupdate_hook`/bindgen as the observed failure rather than `aws-lc-sys`.

No code or ledger state was modified. Target `vibe-kanban/` remains clean (`git status --porcelain` empty at `d5cbb5380fa0b32e98ef9b8d987f63decce4be3a`).
