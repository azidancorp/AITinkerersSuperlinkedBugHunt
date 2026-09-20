# Who-Targets-Me — EU collection-exclusion bypass via country-key mismatch (W5a / #131)

- **Target:** `Who-Targets-Me/` browser extension, pinned HEAD `64e9989c65ba83e8536e57768e19ff0b6409abda` (verified, repo untouched — `git status --porcelain` empty at audit time)
- **Verdict:** **TP (true positive)** — independently re-audited and re-gated by a second-opinion agent, 2026-09-20; differential **3/3 YES** on the audit re-run
- **Class:** privacy / consent-boundary bypass (CWE-359 exposure of private information) — the extension's own EU collection opt-out fails for users who register after install
- **Evidence:** `wtm-w5a-evidence/` next to this report — second-opinion gate re-run log (`gate-rerun-20260920.log`), fidelity audit (`fidelity-check.txt`), cited real-source excerpts (`source-excerpts.txt`). Harness: `scratch/verify/Who-Targets-Me-W5a/w5a-replay.cjs`.

## Claim under test

> The daemon suppresses rawlog collection for EU users by checking `readStorage("userCountry")` in `handleActions` (`src/shared/handlers/onMessageEventHandler.js:69-72`). But registration (`src/shared/handlers/handleUserRegistration.js:11-12`) stores the registered user's country under `userData.country` — never `userCountry`. The only writer of `userCountry` is the `onInstalled` listener (`src/shared/handlers/onInstalledBackgroundEventListener.js:36-42`), which calls `handleUserCountry()` — and that returns `""` whenever no `general_token` exists, i.e. always on a fresh install before registration. A user who installs the extension and then registers from an EU country therefore has **no `userCountry` key at all**, the gate passes, and `SEND_RAW_LOG` collection proceeds.

## Verdict justification (second-opinion audit)

Audited, not trusted: harness read line-by-line and diffed against HEAD; every link in the chain re-derived from the real sources; gate re-run from clean state.

1. **Fidelity.** The harness loads the *actual HEAD source* of `onMessageEventHandler.js` (resolved from the repo path) into a `node:vm` context with only imports stripped. Empirically verified: the transform removes exactly the two `import` statements (+ one blank separator; 86 → 73 code lines), leaves **zero** residual `import`/`export` tokens, and the gate block (`const userCountry = await readStorage("userCountry"); if (userCountry && euCountries.includes(...)) return;`) and the `SEND_RAW_LOG` case are **byte-verbatim** in the executed source. It is not a reimplementation. Mocks cover platform primitives only (`readStorage`/`setToStorage`/`removeFromStorage` over a flat store — matching the real `chrome.storage.local` key semantics of `src/shared/utils/{readStorage,setToStorage}.js`; `sendRawLog` counted; `getUser().isLoggedIn = true`, the honest post-registration state; `euCountries: ["de","fr"]`, a faithful subset — `"de"` is in the real list at `src/shared/utils/eu-countries.js:8`).
2. **State honesty.** Vuln-arm storage is exactly what HEAD's flow produces: `handleUserRegistration.js:11-12` writes `general_token` and `userData.country` and nothing else; repo-wide grep shows `userCountry` is *written* by one place only — `onInstalledBackgroundEventListener.js:36-42` — which stores it only when `handleUserCountry()` returns non-empty, and that returns `""` pre-account (`handleUserCountry.js:7`). So post-registration `userCountry` is genuinely **absent** (real `readStorage` would resolve `null`; the mock resolves `undefined` — both falsy, identical gate behavior). The control is identical-minus-trigger: it adds only `userCountry: "de"`, the single key the gate was designed to consult.
3. **Effect is the boundary itself.** Vuln arm: `sendRawLog invocations: 1` — collection *proceeds* for the EU user (exit 1, canary marker). Control arm: `sendRawLog invocations: 0` — collection suppressed (exit 0). The only difference between arms is the storage key; the only difference in outcome is whether the privacy gate fires. No incidental output differs.
4. **Gate from clean, my run.** `python3 funnel.py verify 131 --repeat 3` (commands unchanged — the audit found the harness faithful): **3/3 replay pairs YES**, stdout hashes byte-identical to the prior lane's runs (`2c679e85eeca143b` vuln / `2723ec394f656c1d` control) — deterministic, reproducible.

## Sub-claims

| # | Sub-claim | Result |
|---|-----------|--------|
| 1 | Gate reads `userCountry` (`onMessageEventHandler.js:69`) and suppresses `SEND_RAW_LOG` for EU values | **Confirmed** — real source, lines 69-77; control arm shows suppression |
| 2 | Registration writes country only to `userData.country` (`handleUserRegistration.js:12`) | **Confirmed** — file read; no `userCountry` write anywhere in the registration path |
| 3 | `userCountry` has exactly one writer, the `onInstalled` listener, which no-ops pre-account | **Confirmed** — repo-wide grep (2 files mention the key: the writer and the gate reader); `onInstalledBackgroundEventListener.js:37-41` skips the write when `handleUserCountry()` returns `""`; `handleUserCountry.js:5-7` returns `""` without a `general_token` |
| 4 | Therefore a fresh-install-then-register EU user has no `userCountry` and is collected | **Confirmed dynamically** — vuln arm drives the real handler with exactly that state; `sendRawLog` invoked |
| 5 | Control (state + `userCountry="de"`) is the identical-minus-trigger comparator | **Confirmed** — harness lines 38-44: same token, same `userData`, one added key |

Secondary facet (code-confirmed, **not** separately replayed): `userCountry` is never cleared or refreshed on account deletion/re-registration (`handleUserDeletion.js:4-5` removes only `general_token` and `userData`; the `onInstalled` writer only writes when the key is absent), so a stale country can also misclassify a user who re-registers elsewhere.

## Method

- Offline, canary-only (`canary-token-de-user`, `canary-ad-payload`); no network, no real browser, no real credentials; repo treated read-only.
- Real HEAD source executed verbatim under `node:vm` with import statements stripped (stripping verified byte-exact — see `wtm-w5a-evidence/fidelity-check.txt`).
- Differential: identical storage state, identical message; the control adds only the `userCountry` key the gate consults. Each run is a fresh process = clean state. Ledger writes only via `funnel.py`.

## Commands

```
node scratch/verify/Who-Targets-Me-W5a/w5a-replay.cjs vuln     # post-registration state, userCountry absent
node scratch/verify/Who-Targets-Me-W5a/w5a-replay.cjs control  # same state + userCountry="de"
python3 funnel.py verify 131 --repeat 3 --verbose              # second-opinion gate re-run (3/3 YES)
```

## Captured output (second-opinion gate re-run, ×3 pairs)

```
vuln    rc=1  sha=2c679e85eeca143b   storage keys: ["general_token","userData"]                 sendRawLog invocations: 1  CANARY-COMPROMISED
control rc=0  sha=2723ec394f656c1d   storage keys: ["general_token","userData","userCountry"]  sendRawLog invocations: 0  CLEAN

differential vs control: 3/3 replay pair(s) YES
```

Full log: `wtm-w5a-evidence/gate-rerun-20260920.log`.

## Falsification criteria checked

- **Harness reimplements the bug** — refuted: the executed text is HEAD's file minus imports; gate and `SEND_RAW_LOG` case byte-verbatim (fidelity-check.txt).
- **Registration actually sets `userCountry`** — refuted: `handleUserRegistration.js:10-13`; repo-wide grep for the key.
- **Fresh installs still get `userCountry` from somewhere** — refuted: sole writer is the `onInstalled` listener; it no-ops when `handleUserCountry()` returns `""`, which it always does pre-account. The `chrome.runtime.reload()` issued at registration (`onMessageEventHandler.js:46`) does not fire `onInstalled`.
- **Mock list invented the EU membership** — refuted: `"de"` is in the real `eu-countries.js`.
- **Differential is incidental output, not the gate** — refuted: the arms differ only in the `sendRawLog` invocation count driven by the gate's own branch.

## Honest impact

**Demonstrated:** a user who installs the extension and then registers from an EU country is **not excluded** from rawlog collection — `SEND_RAW_LOG` handling proceeds and the upload primitive is invoked — solely because the registration flow stores the country under a different storage key (`userData.country`) than the one the exclusion gate reads (`userCountry`). This violates the extension's own EU opt-out for that user. **Not demonstrated (do not claim):** what the backend does with the collected data, real-browser timing, how long the window lasts in wall-clock terms (it ends at the next `onInstalled`-triggered refresh that runs while a token exists — extension/browser update events), and the stale-country secondary facet, which is code-confirmed but unreplayed.
