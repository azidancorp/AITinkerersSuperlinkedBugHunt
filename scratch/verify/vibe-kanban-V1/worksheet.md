# V1 / ledger #105 (+dup #110) — reflected XSS in OAuth handoff error page — verification worksheet

Date: 2026-09-20 · Verifier: independent replication lane (pre-submission check)
Result: **VERIFIED — differential gate 1/1 YES on both #105 and #110**

## What was claimed (ledger #105/#110)

`handoff_complete` (`crates/server/src/routes/oauth.rs:156-213` @ HEAD
d5cbb5380f) reflects the attacker-controlled `error` query parameter
UNESCAPED into a `text/html` response (oauth.rs:160-165 →
`simple_html_response` :435-462; no HTML escaping anywhere in
`crates/server/src`). The branch fires BEFORE the handoff-state lookup, so
any syntactically valid `handoff_id` UUID works. The route sits behind only
`validate_origin` (routes/mod.rs:70-86), which passes requests with no
`Origin` header (origin.rs:48-50) — and browsers send no `Origin` on
top-level GET navigations (link clicks). Result: a one-click reflected XSS
on the app origin, where same-origin JS can call the unauthenticated local
API — including `GET /api/auth/token` (oauth.rs:282-297, live auto-
refreshing cloud access token) and the routes enumerated in the V2/#106
worksheet (config write, PTY, workspace-start agent spawn).

## Source verification (all at HEAD d5cbb5380f, read-only)

| Claim | Verdict | Evidence |
|---|---|---|
| error branch before handoff-state check, unescaped format! into HTML | CONFIRMED | oauth.rs:160-165; sink :449 `<p class="title">{message}</p>` |
| No escaping anywhere in crates/server/src | CONFIRMED | grep: no html_escape/ammonia/v_htmlescape dep in server crate; `simple_html_response`/`close_window_response` are raw `format!` |
| content-type text/html | CONFIRMED | oauth.rs:458 |
| Route behind only validate_origin (+ relay-signature no-op for local) | CONFIRMED | routes/mod.rs:44,70-86; relay_request_signature.rs:35-37 (`!is_relay_request → next.run`) |
| No-Origin GET passes validate_origin | CONFIRMED | origin.rs:48-50 + repo's own test `no_origin_header_allows_request`; runtime-verified in V2 gate |
| handoff_id must be present + valid UUID | CONFIRMED | oauth.rs:145 (`handoff_id: Uuid`, not Option) — **ledger #105's original curl omitted it and would have 400'd on Query rejection without ever reaching the handler; replay uses a valid nil UUID. Claim unaffected, original cmd was malformed.** |
| GET /api/auth/token returns live access token, no auth extractor | CONFIRMED (source) | oauth.rs:90,282-297; same /api layer, no auth extractor anywhere (V2 worksheet) |
| Browsers send no Origin on top-level GET navigation | standard-knowledge | Chrome/Firefox/Safari send Origin only on POST/PUT/fetch-cors etc., never on plain GET navigation; server checks no Sec-Fetch-* headers |

Lineage: error-reflection shape present since the handoff flow was added;
page template `simple_html_response` never had escaping.

## Runtime replay (the gate)

Harness `scratch/verify/vibe-kanban-V1/` (same pattern as V2/#106 — the full
server cannot be built offline, see V2 worksheet "Reproduction"):

- `src/main.rs` — real `origin.rs` BYTE-IDENTICAL via `#[path]`; five spans
  of the real `oauth.rs` copied VERBATIM (icon const :27, styles :32-67,
  `HandoffCompleteQuery` :143-154, error+missing-code branches :160-172,
  `simple_html_response` :435-461). Only the handler TAIL (handoff-state
  lookup + remote redeem → needs `DeploymentImpl` + egress) is stubbed; it
  is not the code under test.
- `fidelity_check.py` — asserts HEAD == d5cbb5380f and every span occurs
  verbatim in the repo file. **FIDELITY OK (5/5 spans).**
- Wiring mirrors routes/mod.rs:70-86: `/api` nest +
  `ValidateRequestHeaderLayer::custom(validate_origin)`.
- `v1-replay.py` — raw-socket GETs, exact header control.

```sh
cd scratch/verify/vibe-kanban-V1
cargo +1.97.1 build --offline        # ~8 s, warm cache
sh v1-vuln.sh      # expect 3/3 REFLECTED
sh v1-control.sh   # expect 4/4 clean
```

## Measurements

Vuln run (no-Origin GET, models a link click):

| Shape | Payload in `error` | Result |
|---|---|---|
| P1 | `<svg onload=alert(document.domain)>` | **400, text/html, reflected unescaped** |
| P2 | `<script>alert(document.domain)</script>` | **400, text/html, reflected unescaped** |
| P3 | `<img src=x onerror=alert(document.domain)>` | **400, text/html, reflected unescaped** |

`VULN_EFFECT=observed (3/3)` — full raw response for P2 in
`evidence-p2-response.txt` (payload sits verbatim inside
`<p class="title">…</p>` in a `text/html; charset=utf-8` 400 body; browsers
render 400 HTML and execute scripts).

Control run:

| Shape | Result |
|---|---|
| K1 benign `error=access_denied` | 400 text/html, message rendered, NO script elements / event-handler attributes (page's only `<img>` is the static base64 logo) |
| K2 valid UUID, no params | 400, real "Missing app_code in callback" branch — handler logic genuinely reached |
| K3 same payload WITH `Origin: http://evil.example` | **403 from validate_origin** — the gate is live; only the no-Origin (browser navigation) shape passes |
| K4 payload but NO `handoff_id` | 400 axum Query rejection, NO reflection (documents #105's malformed original cmd) |

`CONTROL_EFFECT=clean (4/4)`.

Gate: `funnel.py verify 105` and `verify 110` →
`differential vs control: 1/1 replay pair(s) YES` each
(vuln sha `678960958955c097` vs control sha `253a98fffb66403a`).

## Adversarial self-check

- **Is reflection actually executable?** Yes: response is `text/html`, body
  is a full HTML document, payload lands inside `<p class="title">` with no
  encoding. `<script>` injected mid-document executes on parse. A 400 status
  does not prevent rendering/scripting in any browser.
- **Does the victim need any state?** No — the error branch fires before
  `take_oauth_handoff`, so no in-flight OAuth attempt is needed. The
  attacker needs the server's port (OS-assigned when `BACKEND_PORT`/`PORT`
  unset, written to the port file; fixed when packaged). That is a delivery
  detail of the malicious link, not a property of the bug; the page's own
  origin is where the victim's app UI is already open.
- **Token-theft chain runtime-tested?** The reflection is runtime-verified;
  `/api/auth/token` being unauthenticated on the same origin is
  source-confirmed + the V2 gate already runtime-proved an arbitrary /api
  route is reachable with attacker-shaped headers. A logged-in (remote/
  relay) deployment is required for a live token to exist; offline we cannot
  mint a real one (canary-first rule). Impact wording in the report must say
  "same-origin JS gains the full unauthenticated local API incl.
  /api/auth/token" — not "we stole a token".
- **Chrome PNA caveat:** top-level navigation to 127.0.0.1 is not PNA-gated;
  the reflected page then runs same-origin, so subsequent fetches are
  same-origin too. No PNA obstacle for this vector (unlike V2's rebinding).
- **Could the real binary differ?** The code under test is verbatim HEAD
  source; the only replaced part (state lookup/redeem) runs AFTER the
  vulnerable branch and cannot affect it. Query extraction (serde +
  serde_urlencoded percent-decoding) is the same axum 0.8 stack the repo
  pins (Cargo.lock: axum 0.8.8, uuid 1.23.0).
- **Duplicate rows:** #105 and #110 are the same claim with near-identical
  titles (evaded the dedupe key). Both gate-verified here with the identical
  harness; **#105 is the canonical row, #110 should be treated as its dup**
  (one report, not two).
