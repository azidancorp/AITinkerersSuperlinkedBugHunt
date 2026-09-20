# Who-Targets-Me — stale auth token after account switch: uploads authenticated as the previous account (W8 / #132)

- **Target:** `Who-Targets-Me/` browser extension, pinned HEAD `64e9989c65ba83e8536e57768e19ff0b6409abda` (verified, repo untouched — `git status --porcelain` empty at audit time)
- **Verdict:** **TP (true positive)** — independently audited and re-gated from clean by a second-opinion agent, 2026-09-20 (differential 3/3 YES, twice: prior lane + this audit)
- **Class:** stale credential / data integrity — CWE-613 (insufficient session expiration on the client side): the extension keeps using a bearer token after the account it belongs to was switched away
- **Evidence:** `wtm-w8-evidence/` next to this report — `w8-replay.cjs` (audited copy) plus captured outputs `vuln-run{1,2,3}.txt` / `control-run{1,2,3}.txt` and `rc-summary.txt`

## Claim under test

> `src/shared/api/app.js:7-15` reads `general_token` from extension storage exactly once, in an async IIFE at module load, and bakes the value into the feathers REST client's `Authorization` header for the lifetime of the background context. When the stored token subsequently changes via the `storeUserToken` message path (`src/shared/handlers/onMessageEventHandler.js:55-57`) — which writes storage but performs no client rebuild and no `chrome.runtime.reload()` — every upload via `sendRawLog` still goes out authenticated as the **previous** account.

## Verdict justification

The replay harness loads the **actual HEAD source** of `src/shared/api/app.js` into a `node:vm` sandbox (only `import`/`export` syntax stripped — transform diffed against the repo file: the token-capture IIFE, the `app.configure(restClient.fetch(fetch, {headers: {Authorization: token}}))` call, and the singleton export are verbatim). With `@feathersjs/client`, `readStorage` and `fetch` stubbed, the real init IIFE captures `canary-token-account-A`. The vuln arm then applies exactly the state change HEAD's `storeUserToken` flow produces (`setToStorage("general_token", B)` → `chrome.storage.local.set({general_token: B})`, modelled as a backing-store write; that path verifiably has **no** other side effect — the repo contains no `chrome.storage.onChanged` listener and no reload outside the registration branch), and issues an upload through the same service `sendRawLog` uses (`submit-rawlogs`). The outgoing `Authorization` header still carries `canary-token-account-A` while storage holds `canary-token-account-B` → `CANARY-COMPROMISED`, rc 1. The control arm is identical minus the storage flip and shows the current token (`CLEAN`, rc 0). Held 3/3 in the prior lane and 3/3 again in this audit's clean re-gate, with byte-identical stdout hashes both times (`25e8a212ef3d9e68` vuln / `54d031b751b0152d` control).

A maintainer comment corroborates the mechanism: the registration branch reloads the extension precisely because *"This reload is necessary to get the extension up-to-speed, like the token used to post rawlogs"* (`onMessageEventHandler.js:45-46`) — the developers knew the client caches the token and relied on a reload, but wired it only on the registration path.

## Sub-claims

| # | Sub-claim | Result |
|---|-----------|--------|
| 1 | Token read once at module init and baked into the client's static headers | **Confirmed** — `app.js:7-23`: the IIFE runs once at load; the headers object is constructed once with the string value captured at that moment. Under any feathers implementation a static headers object cannot re-read storage at request time |
| 2 | The stored token can change afterwards without the client refreshing | **Confirmed** — `onMessageEventHandler.js:55-57` (`storeUserToken` → `setToStorage`) and `handleUserDeletion.js:4` (`removeFromStorage("general_token")`) both mutate storage with no reload and no `app` re-configure. Repo-wide: the only `chrome.runtime.reload()` is `onMessageEventHandler.js:46` (registration path); no `chrome.storage.onChanged` listener exists anywhere in `src/` |
| 3 | Uploads route through the stale-configured singleton | **Confirmed** — `sendRawLog.js` imports the module-level `app` singleton and calls `app.service("submit-rawlogs").create(apiPayload)` (`:4-19`); the replay exercises that exact service call |
| 4 | Per-call token reads were possible (i.e. this is a defect, not a platform constraint) | **Confirmed by contrast** — `handleUserCountry.js:5-9` reads `general_token` fresh at call time and passes it per request; only the upload client bakes it |
| 5 | Differential behaviour (stale header on switch, current header without switch) | **Confirmed 3/3 ×2** — see Captured output |

## Method (second-opinion audit)

- Offline, canary-only (`canary-token-account-A` / `canary-token-account-B`); no network, no real credentials; repo strictly read-only.
- Fidelity: real `app.js` source executed in `node:vm`; the token-capture logic is **not** reimplemented. The feathers stand-in only preserves the call shape `feathers().configure(restClient.fetch(fetch, {headers}))` → `.service(name).create(...)`; because it re-uses the configured headers object at request time, it is the *most charitable* dynamic interpretation possible — and the header is still stale, since the string was read once by the real code. The stub therefore cannot manufacture the false positive.
- Trigger honesty: the vuln arm's A→B flip is the exact storage event the real `storeUserToken` flow produces; verified that flow has no other observable effect on the client. Control is identical-minus-trigger.
- Assertion honesty: the verdict compares the outgoing header to the *currently stored* token. The control arm also rules out harness-broken false positives: had the init IIFE failed (catch path, empty token), the control would exit 1 too and the differential would collapse.
- Audit fix applied: harness service name corrected `raw-logs` → `submit-rawlogs` to match the real `sendRawLog` upload path. Output-neutral — stdout hashes unchanged before/after, matching the prior lane's ledger records byte-for-byte.

## Commands

```
node scratch/verify/Who-Targets-Me-W8/w8-replay.cjs vuln      # rc=1, CANARY-COMPROMISED
node scratch/verify/Who-Targets-Me-W8/w8-replay.cjs control   # rc=0, CLEAN
python3 funnel.py verify 132 --repeat 3 \
  --vuln    'node /home/azidan/AQL/AI/AITinkerers/scratch/verify/Who-Targets-Me-W8/w8-replay.cjs vuln' \
  --control 'node /home/azidan/AQL/AI/AITinkerers/scratch/verify/Who-Targets-Me-W8/w8-replay.cjs control'
# differential vs control: 3/3 replay pair(s) YES
```

## Captured output (×3 each, this audit's clean re-gate)

```
vuln run (identical ×3, rc=1):
mode: vuln
current stored general_token: canary-token-account-B
outgoing Authorization header: canary-token-account-A
CANARY-COMPROMISED: upload authenticated as previous account (stale token captured at module init)

control run (identical ×3, rc=0):
mode: control
current stored general_token: canary-token-account-A
outgoing Authorization header: canary-token-account-A
CLEAN: upload carried the current token
```

Raw files: `wtm-w8-evidence/vuln-run{1,2,3}.txt`, `wtm-w8-evidence/control-run{1,2,3}.txt`, `wtm-w8-evidence/rc-summary.txt` (vuln rc=1 / control rc=0, all three pairs).

## Falsification criteria checked

- **"The client re-reads the token per request"** — refuted: the read sits inside a once-only module-load IIFE; the headers object is static. Verified against the verbatim source, not the stub.
- **"Every token change reloads the extension"** — refuted: only registration reloads (`:46`); `storeUserToken` and user deletion do not, and no storage-change listener exists to re-configure the client.
- **"The harness fakes the capture logic"** — refuted: real HEAD source runs in the vm; the transform strips only module syntax (diffed). The stale value comes from the real IIFE's capture.
- **"A broken harness could exit 1 spuriously"** — refuted by the control arm: any such failure mode (IIFE rejection → empty token, missing client) would flip the control to rc 1 and destroy the differential; control is deterministically CLEAN.
- **"Registration path makes it unreachable"** — refuted: `storeUserToken` is a shipped, reachable message path (relayed verbatim by the content script from any same-window `postMessage`, per W1/#101 — a compounding factor, not a requirement for this finding).

## Honest impact

**Demonstrated:** after a storage-level token change, the extension **sends** its uploads (`submit-rawlogs`) authenticated as the **previous** account — the outgoing `Authorization` header carries the stale token while extension storage holds the new one. That is (a) **misattribution / data-integrity corruption**: rawlogs are submitted under credentials the user believes they switched away from, and (b) **stale-credential use** (CWE-613): the previous account's bearer token keeps being transmitted after the switch. The deletion variant is the same class: after `deleteWTMUser` removes the token, uploads would still carry the deleted account's token (no reload on that path either). Exposure window: on MV2 builds (`v2.manifest.template.json`, persistent background page) the staleness lasts for the rest of the browser session; on MV3 builds (`v3.manifest.template.json`, service worker) it lasts until the browser recycles the worker — and continuous collection events keep the worker alive.

**NOT demonstrated — do not claim:** backend acceptance of the stale pairing, what the server does with a stale token, or any cross-account data *read*. The harness proves the client-side header staleness only; server-side authorisation decisions were not tested (offline, canary-only). Registration-triggered account creation is unaffected (it reloads).
