# CVSS v3.1 base-score assessment — all confirmed findings

Assessment date: 2026-09-20; **revised same day** (arithmetic correction, see
revision note below). Scope: the nine confirmed findings in
`confirmed-vulnerabilities/`, cross-referenced to ledger rows
(`.funnel/funnel.db`) and to `claimed-vulnerabilities.md` (claim IDs V1, V2,
W1, W2, W5a, W8, S1, S2, P8).

Scores are **base only** — no temporal, environmental, or modified-base
modifiers. Metric choices are grounded in each report's own "Honest impact"
and "Not demonstrated / do not claim" sections, not in the claim's title.

> **Revision note (2026-09-20, second pass).** Every Scope-Changed score in
> the first revision was computed with a wrong impact sub-formula (a linear
> `3.25 × (ISS − 0.97)` term instead of the spec's 15th-power
> `3.25 × (ISS − 0.02)^15` soft cap), understating or overstating several
> rows; all Scope-Unchanged rows were correct. The equations were re-verified
> against the FIRST CVSS v3.1 specification document (§7.1) and every score
> recomputed with `scratch/cvss31.py`, which reproduces six canonical
> anchor vectors exactly (5.3 info-leak shape, 6.1 reflected-XSS shape, 7.5
> remote-DoS shape, 9.6 CSRF-to-RCE shape, 9.8, 10.0). Vector choices are
> unchanged from the first revision — only the derived numbers are corrected.

## Scores

| Rank | Finding | Ledger | Vector | Score |
|---|---|---|---|---|
| 1 | V1 — OAuth handoff reflected XSS | #105 / #110 | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` | **9.6 Critical** |
| 1 | W1 — unvalidated page→background bridge | #120 / #122 | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H` | **9.6 Critical** |
| 1 | W2 — registration token → page origin | #121 | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L` | **9.6 Critical** |
| 4 | V2 — origin bypass / DNS rebinding | #106 | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` | **8.8 High** |
| 5 | S2 — slow-connection worker starvation | #112 | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **7.5 High** |
| 5 | S1 — unbounded header memory | #111 | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | **7.5 High** |
| 7 | W8 — stale token misattribution | #132 | `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | **6.1 Medium** |
| 8 | P8 — rustls advisory pin | #127 | `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N` | **3.7 Low** |
| 9 | W5a — EU exclusion bypass | #131 | `AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N` | **3.3 Low** |

**Three findings reach Critical (9.6) — V1, W1 and W2 — despite each
requiring `UI:R`.** V1 and W1 share the canonical CSRF-to-RCE vector shape
(`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`); W2 differs only in `A:L` and lands
on the same 9.6. The first revision's "nothing reaches Critical" headline
was an artefact of the arithmetic error, not of the metric choices. What
separates the rest from the top is impact and scope, not exploitability:
W8 carries a partial impact vector, V2 is capped by `S:U`, and the snare
pair is availability-only.

## Metric rationale

### V1 — OAuth handoff reflected XSS (9.6)

- `S:C` — standard treatment for reflected XSS: vulnerable component is the
  server, impacted security authority is the victim's browser.
- `UI:R` — victim must load the crafted URL. The error branch fires
  **before** the handoff-state lookup (`oauth.rs:160-165`), so no session,
  cookies, or in-flight OAuth attempt is required.
- `C:H/I:H/A:H` — confirmed same-origin API surface: `GET /api/auth/token`
  (live auto-refreshing cloud token), `PUT /api/config`, PTY websocket,
  `POST /api/workspaces/start` agent spawn.
- Cross-site reachability depends on `origin.rs:48-50` passing no-Origin
  requests — i.e. on V2. See the filing note below.

### W1 — unvalidated page→background bridge (9.6)

- `S:C` — the bridge is the vulnerable component; the impacted authorities
  (privileged background handlers, extension storage, the user's backend
  account) sit outside the extension's authorisation scope.
- `AC:L`, `PR:N` — any page-world script on a matched origin qualifies with
  zero privileges. `site-matches.json` covers facebook, x, instagram,
  youtube, ~200 google TLDs.
- The **ungated** subset alone (`storeUserToken`, `deleteWTMUser`,
  `registerWTMUser` + `chrome.runtime.reload()`) already yields
  `C:H/I:H/A:H`. The `isLoggedIn`/non-EU precondition on `SEND_RAW_LOG` and
  `UPDATE_USER` therefore does not lower the score.

### W2 — registration token → page origin (9.6)

- Identical exploitability to W1 (`S:C`, `AC:L`, `PR:N`, `UI:R`); the
  difference is reach, not score.
- `A:L` rather than `A:H` because the DoS path is speculative; under the
  corrected formula the choice does not move the rounded score (9.6 either
  way).
- The disclosed bearer token is the `Authorization` credential for
  `data-api.whotargets.me` (`app.js:13`), so disclosure implies full account
  read/write.
- Report's own caveat to carry into the submission: registration is a
  one-time event and the token lands on whichever tab is focused when the
  API responds — narrow per-user window, but the stored page-origin copy is
  permanent until the user clears site data.

### V2 — origin bypass / DNS rebinding (8.8)

- `S:U` — the impacted resources are exactly what `validate_origin`
  authorises; the local API is inside the middleware's own scope.
- `AC:L` — same-port rebinding is an extra condition, but it is fully
  attacker-controlled and tooling-standard. See the sensitivity table.
- `C:H/I:H/A:H` — directory listing, config overwrite, `/api/auth/token`,
  PTY, agent spawn with attacker-chosen `executor_config` and `prompt`.
- **Root cause of V1's cross-site reachability.** V1 exploits the no-Origin
  pass at `origin.rs:48-50`.

### S1 / S2 — snare pre-auth DoS (7.5 each)

- The canonical unauthenticated-DoS shape: `UI:N` (pure server-side, no
  victim interaction) and `A:H` (total availability loss while sustained —
  which the spec counts as high).
- The two are **distinct**, confirmed by their own measurements: S2 fails
  probes at the 17-connection threshold; S1 grows RSS 5→209 MiB on a single
  connection while still answering 6/6 probes.
- Both compose — dribbling the flood also parks a slot — but each stands
  alone.

### W8 — stale token misattribution (6.1)

- Lowest-confidence score in the set. `I:L` because the report explicitly
  states backend acceptance of the stale token is **not demonstrated**.
- If the backend accepts the stale bearer (it *is* a valid token for a real
  account), integrity rises to `I:H` and the score to **8.2**.
- Cross-user account switching would additionally add `C:H`.

### P8 — rustls advisory pin (3.7)

- Scored as the *underlying* rustls flaw in pizauth's context, not as a
  pin-presence observation.
- `AC:H` — exploitation requires a malicious or compromised TLS peer: the
  optional `https_listen` callback client, or the OAuth2 provider (or
  something controlling it) for ureq outbound.
- `I:L` only — the advisory rules out on-path use and states the handshake
  transcript stays authenticated.
- Default deployment is loopback HTTP, which deflates it further. Do **not**
  escalate to "on-path attacker breaks TLS".

### W5a — EU exclusion bypass (3.3)

- CVSS is a poor fit: there is no external attacker, and the defect is a
  storage-key mismatch in the user's own extension state.
- `AV:L`, `UI:R` — install the extension, then register.
- The real cost is regulatory (GDPR), not exploitability.
- If instead credited via the page-script path — W1's ungated
  `registerWTMUser` writes `userData.country` but never `userCountry`, so a
  malicious page can force the gate to fail — that is a **W1 escalation**,
  not a re-rating of W5a.

## Sensitivity

| Finding | Swing | Driver |
|---|---|---|
| W1 | 9.6 → **10.0 Critical** | `UI:N`, if browsing an ad-heavy matched site is not counted as user interaction |
| W1 | 9.6 → 8.8 | `S:U` |
| W1 | 9.6 → 8.3 | `AC:H`, pricing "attacker script already running on a matched top-tier origin" as a condition beyond the attacker's control (second-opinion reading) |
| W2 | 9.6 → 8.3 | `S:U` |
| W2 | 9.6 → 7.4 | disclosure-only reading (`C:H/I:N/A:N`), treating token use as a separate step |
| W2 | 9.6 → 8.2 | `AC:H` (same second-opinion prerequisite as W1 above) |
| W1 | 9.6 → 8.1 | `AC:H` + `UI:N` + partial impact (`C:L/I:H/A:L`) — the second opinion's full alternative vector |
| W2 | 9.6 → 6.8 Medium | `AC:H` + `UI:N` + `C:H/I:N/A:N` — the second opinion's full alternative vector (drops a band) |
| V1 | 9.6 → 8.8 | `S:U` |
| V2 | 8.8 → **9.6 Critical** | `S:C`, if agent-spawn RCE is counted as beyond the middleware's authz scope |
| V2 | 8.8 → 7.5 | `AC:H`, if same-port rebinding is judged a special condition |
| W8 | 6.1 → 8.2 | `I:H`, if backend acceptance of stale tokens is assumed |

## Filing recommendations

1. **File V1 and V2 as a pair, not as independent findings.** V1's
   cross-site reachability *is* V2's no-Origin pass. Two separate top scores
   for one root cause invites a reviewer to discount both. File V2 as the
   root cause and V1 as its demonstrated exploit path.
2. **Lead the Critical/High submissions with the caveat their reports already
   contain.** A 9.6 filed with an honest impact paragraph survives review
   better than a 10.0 that doesn't. FP scoring is zero.
3. **V1's token-theft chain is source-confirmed, not runtime-demonstrated.**
   State that explicitly; do not imply a live token was exfiltrated.
4. **W8's 6.1 is gated on backend behaviour that was never tested.** Either
   say so, or do not claim the integrity impact at all.
5. **P8 needs `funnel.py report 127` before the T+4:30 freeze** — it is the
   only verified row with a report skeleton still pending.

## Evidence basis

Every score above is traceable to a measured claim in the corresponding
finding report:

- V1: unescaped reflection of three payload shapes into `text/html`,
  controls 4/4 clean, differential YES on #105 and #110.
- V2: seven header shapes against byte-identical HEAD `origin.rs` under
  production layer wiring, differential 3/3 YES.
- W1: `storeUserToken` overwrite and `sendRawLog` injection, 3/3 each.
- W2: canary token into page-origin localStorage plus one
  `postMessage(...,"*")`, 3/3.
- S1: RSS 5→209 MiB (204 MiB Δ, 1.06× input) on one connection, flat
  control at identical volume, 3/3.
- S2: threshold of 17 held connections, total denial while ≥17, ~3 s
  recovery, idle-connection self-heal.
- W5a / W8: `sendRawLog` invocation count and outgoing `Authorization`
  header respectively, 3/3 each on the audit re-gate.
- P8: `Cargo.lock:1395-1396` pin at 0.23.43 inside `>=0.23.13,<0.23.45`;
  `cargo tree -i rustls` confirms it is a live dependency path, not a stale
  lockfile entry.
