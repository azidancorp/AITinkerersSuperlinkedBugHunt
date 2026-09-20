# Who-Targets-Me — registration bearer token disclosed to page origin (W2 / #121)

- **Target:** `Who-Targets-Me/` browser extension, pinned HEAD `64e9989c65ba83e8536e57768e19ff0b6409abda` (verified, repo untouched)
- **Verdict:** **TP (true positive)** — independently replicated from first principles, 2026-09-20
- **Class:** credential exposure — extension API bearer token written to page-origin `localStorage` and broadcast via `window.postMessage(..., "*")`
- **Evidence:** `wtm-w2-evidence/` next to this report — `harness.mjs` plus captured outputs `vuln-run{1,2,3}.json` / `control-run{1,2,3}.json`

## Claim under test

> When a user registers, the extension background sends the fresh account token to the content script of whichever tab is focused at callback time; that content script writes the token into the PAGE-ORIGIN localStorage and also re-broadcasts it with `window.postMessage(..., "*")`, disclosing the extension's API bearer credential to every script running in the page. The extension itself never reads the page copy back.

## Verdict justification

A registration round-trip makes the background send `{registrationFeedback: response}` — containing the fresh API token — to `tabs[0]` of a `{active: true, currentWindow: true}` query issued **at callback time** (`src/shared/handlers/onMessageEventHandler.js:28` → `src/shared/utils/postMessageToFirstActiveTab.js:3-4`), and the shipped content script writes that token into page-origin `localStorage` and re-broadcasts it with `window.postMessage(request, "*")` (`src/daemon/index.js:13-17`). The full chain was reproduced executing the repo's actual, unmodified source in a `node:vm` (`vm.SourceTextModule`) sandbox with only browser-platform primitives mocked; the clean-state differential (vuln vs. control trigger) held 3/3. The token is the genuine API credential (`src/shared/api/app.js:13` sets it as the `Authorization` header for all API calls). Nothing ever reads the page copy back.

## Sub-claims

| # | Sub-claim | Result |
|---|-----------|--------|
| 1 | Token emitted to tab chosen at callback time (not the initiating tab) | **Confirmed** — `chrome.tabs.query({active:true,currentWindow:true})` runs inside the registration response callback, after the API round-trip; replay delivered the token to the active tab, which was not the trigger's origin |
| 2 | Content script persists token to page localStorage AND re-broadcasts with `"*"` | **Confirmed** statically and dynamically — `pageOriginLocalStorage_general_token = "\"fresh-canary-token-7f3d9a\""`, one `postMessage(..., "*")`, page-script observer received the canary |
| 3 | That content script is shipped | **Confirmed** — webpack entry `index: src/daemon/index.js` for chrome/edge/firefox (`src/build/webpack.daemon.config.js:52,62`), output `daemon/index.js`, referenced by both manifest templates' `content_scripts`. **Note:** `src/contents/index.js` is a dead duplicate with identical listener code, referenced by no build config or manifest — analyses targeting it alone would be vacuous, but the shipped `src/daemon/index.js` carries the same code, so the claim survives. (The older `c115-*.mjs` harnesses import the dead duplicate; do not gate on those.) |
| 4 | Token is the API credential | **Confirmed** — `app.js:9-14` reads `general_token` from extension storage and sets `Authorization: <token>` for the feathers REST client; also used as resource id in `handleUserCountry.js:9` |
| 5 | No code path reads the page copy back | **Confirmed** — repo-wide grep: `localStorage.getItem("general_token")` appears nowhere; every extension read goes through `readStorage` → `chrome.storage.local` (extension-private). The page copy is pure disclosure |

No gating kills the finding: the registration branch (`onMessageEventHandler.js:38-46`) has no consent/country/storage precondition, and the replay seeded **no** storage state — the leak fired from clean state.

## Method

- Offline, canary-only (`fresh-canary-token-7f3d9a`); no network egress, no real credentials.
- Real source: repo files executed verbatim via `vm.SourceTextModule` (true ESM semantics, live bindings, cycles). No re-implementation of extension logic.
- Mocks encode browser platform guarantees only: `chrome.storage.local` = extension-private storage; content-script `localStorage` = page-origin storage (same object page scripts see); `window.postMessage(m, "*")` = delivered to every window `message` listener; `chrome.tabs.query({active,currentWindow})` + `tabs.sendMessage` = background reaches the currently-focused tab's content script; `fetch` = offline stub returning the synthetic canary only.
- Third-party libraries (`@feathersjs/client`, `cheerio`, `jsonpath-plus`, `lodash`, `jquery`) are inert stubs except a minimal feathers REST client stand-in (a library, not extension code); all extension code on the exercised path runs verbatim.
- Differential: vuln trigger `{registerWTMUser: true, ...}` vs. control trigger `{updateYGTab: true}` (a real, unrelated extension message). Identical setup otherwise. Each run is a fresh process = clean state.

## Commands

```
node --experimental-vm-modules harness.mjs vuln     # trigger: {registerWTMUser: true, ...}
node --experimental-vm-modules harness.mjs control  # trigger: {updateYGTab: true}
```

The harness aborts unless `git rev-parse HEAD` matches the pinned `64e9989c65`.

## Captured output (×3 each, exit codes)

```
control run 1 exit=0 verdict="BENIGN"      vuln run 1 exit=0 verdict="VULNERABLE-REPRODUCED"
control run 2 exit=0 verdict="BENIGN"      vuln run 2 exit=0 verdict="VULNERABLE-REPRODUCED"
control run 3 exit=0 verdict="BENIGN"      vuln run 3 exit=0 verdict="VULNERABLE-REPRODUCED"
```

Vuln run (full JSON):

```json
{
  "mode": "vuln",
  "trigger": { "registerWTMUser": true, "political_affiliation": "canary-party", "age": 42, "gender": "x", "postcode": "0", "country": "canaryland" },
  "extensionStorageToken": "fresh-canary-token-7f3d9a",
  "pageOriginLocalStorage_general_token": "\"fresh-canary-token-7f3d9a\"",
  "tabMessagesSent": [{ "tabId": 1, "keys": ["registrationFeedback"] }],
  "postMessageStarCount": 1,
  "pageScriptObserverSawCanary": true,
  "runtimeReloadCalled": true,
  "fetchCalls": [{ "url": "https://canary-data-api.invalid/user-credentials", "method": "POST", "authorization": null }],
  "verdict": "VULNERABLE-REPRODUCED"
}
```

Control run (full JSON):

```json
{
  "mode": "control",
  "trigger": { "updateYGTab": true },
  "extensionStorageToken": null,
  "pageOriginLocalStorage_general_token": null,
  "tabMessagesSent": [],
  "postMessageStarCount": 0,
  "pageScriptObserverSawCanary": false,
  "runtimeReloadCalled": false,
  "fetchCalls": [],
  "verdict": "BENIGN"
}
```

## Differential

**Held 3/3.** Identical setup; only the trigger message differed. Vuln leaked the canary to page storage and to a page-script listener in every run; control leaked nothing in every run. Exit codes: vuln 0 = reproduced, control 0 = benign, all six runs.

## Falsification criteria checked

- **Listener file not shipped** — refuted as a defence: the shipped entry `src/daemon/index.js` contains the listener; `src/contents/index.js` is the (unreferenced) dead duplicate.
- **Message doesn't carry the token** — refuted: replay shows `registrationFeedback` delivering the exact canary returned by the (mocked) registration API.
- **Write/broadcast gated by skipped condition** — refuted: no consent/country/storage gating on the registration branch; leak fired from clean state.
- **Page copy read back by the extension** — refuted: no `localStorage.getItem("general_token")` anywhere; all reads use `chrome.storage.local`. Finding class stands as pure disclosure.

## Honest impact

**Demonstrated:** the extension's own shipped code mechanically copies the fresh API bearer token into page-origin `localStorage` on the focused tab and broadcasts it via `postMessage(..., "*")` to any listener in that page, on every registration, with no read-back. **Platform-guaranteed hypothesis (not re-proven here):** that a malicious or compromised script already running on a matched origin (facebook.com, x.com, instagram.com, youtube.com, whotargets.me, google.*) would in practice be present and listening at that moment — but since content-script localStorage *is* the page's origin storage, the token persists there for any later page script to read at leisure, and the match list covers the highest-traffic sites on the web. Severity caveat: registration is a one-time event per install and the token lands on whichever tab is focused when the API responds — the per-user exposure window is narrow, but the stored copy is permanent until the user clears site data.
