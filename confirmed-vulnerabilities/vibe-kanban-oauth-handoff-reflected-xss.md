# Second-opinion report: vibe-kanban reflected XSS in OAuth handoff error page

- Snapshot tested: `d5cbb5380fa0b32e98ef9b8d987f63decce4be3a` (`git rev-parse HEAD`), ledger candidates **#105** (canonical) and **#110** (same claim, near-identical title — evaded the dedupe key; treat as one finding)
- All testing offline on 127.0.0.1 only; synthetic payloads; harness in `scratch/verify/vibe-kanban-V1/` (kept, not /tmp)
- Gate status: **differential YES on both rows** (`funnel.py verify 105`, `verify 110`; vuln sha `678960958955c097` vs control sha `253a98fffb66403a`), vibe-kanban's second verified claim after #106

## Verdict

**CONFIRMED** (confidence 0.85). `GET /api/auth/handoff/complete` reflects
the attacker-controlled `error` query parameter **unescaped** into a
`text/html` page on the app origin (`crates/server/src/routes/oauth.rs:160-165`
→ `simple_html_response` `:435-461`; sink at `:449`, no HTML escaping
anywhere in `crates/server/src`). The branch fires **before** the
handoff-state lookup, so no in-flight OAuth attempt is needed — any
syntactically valid `handoff_id` UUID works. The only gate on the route is
`validate_origin`, which passes requests with no `Origin` header
(`middleware/origin.rs:48-50`) — and browsers send no `Origin` on top-level
GET navigations, so a **one-click malicious link** yields script execution
on the app origin. From there, same-origin JS reaches the unauthenticated
local API: `GET /api/auth/token` (live auto-refreshing cloud access token,
`oauth.rs:282-297`), config overwrite, PTY websocket, and workspace-start
agent spawn (route inventory source-verified in the V2/#106 report).

Confidence is 0.85 rather than higher because the reflection was replayed
against verbatim HEAD source in a harness (the full server cannot be built
offline — see "Reproduction" in the V2 report), and the token-theft
escalation is source-confirmed, not runtime-demonstrated (a live token needs
a logged-in remote deployment; offline we mint no credentials, per the
canary-first rule). The reflection itself — the vulnerability — is
runtime-verified 3/3 with a 4/4 clean control. The one piece of evidence
that would most change my mind: an end-to-end browser demo against a running
server — which would only *strengthen* the claim.

## Root cause

1. **`oauth.rs:160-165`** — `if let Some(error) = query.error { return
   Ok(simple_html_response(BAD_REQUEST, format!("OAuth authorization failed:
   {error}"))) }`. `error` is a free-form query parameter
   (`HandoffCompleteQuery.error: Option<String>`, `:149`), formatted straight
   into HTML.
2. **`oauth.rs:435-461`** — `simple_html_response` interpolates `message`
   into `<p class="title">{message}</p>` with no escaping and serves
   `content-type: text/html; charset=utf-8`. (The sister template
   `close_window_response` has the same shape; it only prints server-
   generated strings at HEAD, but any future attacker-influenced value lands
   the same way.)
3. **`origin.rs:48-50`** — the sole auth-style middleware on `/api`
   (`routes/mod.rs:70-86`) returns `Ok(())` when no `Origin` header is
   present. Top-level GET navigations (link clicks, redirects from an OAuth
   error) carry no `Origin`, so the reflection is reachable cross-site by
   design. The relay-signature layers on the same routes are no-ops for
   local requests (`relay_request_signature.rs:35-37`).

Supporting facts verified at HEAD:

- `handoff_id: Uuid` is a **required** query field (`oauth.rs:145`) — ledger
  #105's original replay curl omitted it and could never have reached the
  handler (axum Query rejection, control shape K4). With any valid UUID the
  error branch fires first, so the claim stands; only the original cmd was
  malformed.
- Browsers render 400-status HTML bodies and execute their scripts; the
  injected `<script>` runs on parse.
- Server binds loopback only by default (`main.rs:59-80`; port OS-assigned
  unless `BACKEND_PORT`/`PORT` set, written to the port file) — the
  attacker needs the port for the link, a delivery detail, not a property of
  the bug.

## Reproduction (verbatim)

Full server not buildable offline (see V2 report: `libsqlite3-sys` → bindgen
→ `libclang.so`). Replay follows the same **real HEAD source in a harness**
pattern:

- `scratch/verify/vibe-kanban-V1/src/main.rs` — real `origin.rs`
  **byte-identical** via `#[path]`; five `oauth.rs` spans copied **verbatim**
  (`:27`, `:32-67`, `:143-154`, `:160-172`, `:435-461`); only the handler
  tail after the vulnerable branches (handoff-state lookup + remote redeem,
  needs `DeploymentImpl` + egress) is stubbed.
- `fidelity_check.py` — asserts HEAD == d5cbb5380f and every span occurs
  verbatim in the repo file. **FIDELITY OK (5/5).**
- Wiring mirrors `routes/mod.rs:70-86` (`/api` nest +
  `ValidateRequestHeaderLayer::custom(validate_origin)`); `v1-replay.py`
  drives raw-socket HTTP.

```sh
git -C vibe-kanban rev-parse HEAD        # d5cbb5380fa0b32e98ef9b8d987f63decce4be3a
cd scratch/verify/vibe-kanban-V1
python3 fidelity_check.py                # FIDELITY OK
cargo +1.97.1 build --offline            # ~8 s, warm cache
sh v1-vuln.sh      # attacker payloads -> expect 3/3 REFLECTED
sh v1-control.sh   # benign/rejected/cross-origin shapes -> expect 4/4 clean
cd ../../.. && python3 funnel.py verify 105 \
  --vuln  '/home/…/scratch/verify/vibe-kanban-V1/v1-vuln.sh' \
  --control '/home/…/scratch/verify/vibe-kanban-V1/v1-control.sh'
```

## Measurements

Raw-socket `GET /api/auth/handoff/complete` against the harness, no `Origin`
header (models a link click):

| Shape | Result |
|---|---|
| P1 `error=<svg onload=alert(document.domain)>` | **400, text/html, payload reflected unescaped** |
| P2 `error=<script>alert(document.domain)</script>` | **400, text/html, reflected unescaped** (full raw response: `evidence-p2-response.txt`) |
| P3 `error=<img src=x onerror=alert(document.domain)>` | **400, text/html, reflected unescaped** |
| K1 `error=access_denied` (benign) | 400, message rendered, no script elements / event handlers |
| K2 valid UUID, no params | 400, real "Missing app_code in callback" branch — handler genuinely reached |
| K3 P2 payload **with** `Origin: http://evil.example` | **403 from validate_origin** — gate live; only the no-Origin navigation shape passes |
| K4 payload, no `handoff_id` | 400 Query rejection, no reflection |

Gate: `differential vs control: 1/1 replay pair(s) YES` on both #105 and
#110, deterministic stdout hashes, ~35 ms per run.

## Adversarial self-check

- **Does the gate work at all?** Yes — K3 shows the same endpoint 403s when
  a cross-site `Origin` IS present. The finding is not "no check"; it is
  that the browser-navigation shape carries no `Origin` by design.
- **Victim state needed?** None — the error branch precedes the handoff
  lookup. No OAuth attempt, no session, no cookies (the local API has no
  auth extractor at all).
- **Token-theft chain runtime-tested?** No — and the report must say so.
  Runtime-verified: the reflection (this harness) and the reachability of
  arbitrary `/api` routes with attacker-shaped headers (V2 gate).
  Source-confirmed only: `/api/auth/token` returning a live token — which
  additionally requires a logged-in remote deployment.
- **Chrome PNA?** Not an obstacle: top-level navigation to 127.0.0.1 is not
  PNA-gated, and the reflected page's subsequent fetches are same-origin.
- **Could the real binary differ?** No plausible mechanism: the vulnerable
  branch and template are verbatim HEAD bytes; the stubbed tail runs after
  them and cannot affect them; query decoding is the same pinned axum 0.8.8
  / uuid 1.23.0 stack as the repo's Cargo.lock.
- **Mitigation at HEAD?** None. `VK_ALLOWED_ORIGINS` only *adds* allowed
  origins; nothing escapes the template or requires `Origin` on GET.

## Suggested remediation (for the report)

HTML-escape `message` in `simple_html_response` (and audit
`close_window_response`); better, render the error page from a fixed set of
known OAuth error codes instead of echoing the raw parameter. Defence in
depth: validate `handoff_id` state before any error rendering, and see the
V2 report's `validate_origin` hardening (require `Origin` or a startup
bearer token on `/api`).

## Measured vs inferred

Measured: unescaped reflection of three payload shapes into `text/html` on
the app origin (verbatim HEAD source, production layer wiring), benign/
rejected/cross-origin controls 4/4 clean, differential gate YES on both
ledger rows, code fidelity 5/5 spans verbatim, HEAD pin check. Inferred
(standard knowledge): browsers omitting `Origin` on top-level GET
navigations and executing scripts in 400-status HTML. Inferred
(source-confirmed): the downstream unauthenticated API surface incl.
`/api/auth/token` — not runtime-replayed here.

## Artifacts

- Harness, fidelity check, driver, scripts, raw response evidence, full
  worksheet: `scratch/verify/vibe-kanban-V1/`
- Gate log: ledger #105 and #110 `verify_log` (2 runs each)
- Report skeleton: `.funnel/report-105.md` (fields 5/PoC and accuracy notes
  await human pass); do NOT file #110 separately — duplicate of #105
