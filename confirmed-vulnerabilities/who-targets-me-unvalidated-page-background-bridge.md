# Who-Targets-Me — unvalidated page→background message bridge (W1 / #120, #122)

- **Target:** `Who-Targets-Me/` browser extension, pinned HEAD `64e9989c65ba83e8536e57768e19ff0b6409abda` (verified, repo untouched)
- **Verdict:** **TP (true positive)** — independently replicated from first principles, 2026-09-20
- **Class:** broken access control / insufficient input validation on cross-context message bridge (CWE-346, CWE-345)
- **Evidence:** `wtm-w1-evidence/` next to this report — captured outputs for `storeUserToken` and `sendRawLog` cases, 3/3 differential each

## Claim under test

> The content script at `src/daemon/index.js` forwards every same-window `postMessage` verbatim to `chrome.runtime.sendMessage`, checking only `event.source != window`. The background handler `src/shared/handlers/onMessageEventHandler.js` accepts those messages with no sender, origin, or type allowlist. Any page-world script on a matched site can therefore invoke privileged extension handlers, including overwriting the bearer credential (`storeUserToken`), deleting the account (`deleteWTMUser`), registering an attacker-controlled account (`registerWTMUser` + `chrome.runtime.reload`), forging rawlog submissions (`SEND_RAW_LOG`), and mutating consent (`UPDATE_USER`).

## Verdict justification

### Static analysis

`src/daemon/index.js:5-11`:

```js
window.addEventListener("message", async function (event) {
  if (event.source != window) {
    return;
  }
  currentBrowser.runtime.sendMessage(event.data);
});
```

The listener filters only on `event.source != window`. Any script running in the page's main world satisfies `event.source == window`, so its `postMessage` is forwarded unchanged to the extension background.

`src/shared/handlers/onMessageEventHandler.js:14-86` receives the message and branches on properties:

- `request.registerWTMUser` → `handleUserRegistration(...)` then `chrome.runtime.reload()`
- `request.deleteWTMUser` → `handleUserDeletion()`
- `request.storeUserToken` → `setToStorage("general_token", request.token)`
- `request.action == "SEND_RAW_LOG"` → `sendRawLog(payload)` (when user logged in and non-EU)
- `request.action == "UPDATE_USER"` → `user.update(payload)`
- `request.action == "CONSENT_SET_ASK_ME_LATER_DATE"` → `user.setAskMeLaterConsentDate(...)`

No check inspects `sender`, `sender.origin`, `sender.url`, or any message signature. The `SEND_RAW_LOG` and `UPDATE_USER` paths require `user.isLoggedIn` and a non-EU `userCountry`, but the credential-overwrite, account-deletion, and registration/reload paths are ungated.

The bearer credential `general_token` is read by `src/shared/api/app.js:9-13` and sent as the `Authorization` header on every API call. Overwriting it therefore lets a page-world script redirect subsequent API traffic to an attacker account or simply break the extension by deleting the user.

### Dynamic replication

The replay harness `scratch/wtm-bridge-replay.js` loads the **actual, unmodified HEAD source** of both `src/daemon/index.js` and `src/shared/handlers/onMessageEventHandler.js` into a `node:vm` sandbox with only browser-platform primitives mocked (`chrome.runtime`, `window`, `localStorage`, storage API). A synthetic page-world script calls `window.postMessage(...)`; the harness checks whether the privileged background handlers execute.

Two attack shapes were verified against the same benign control:

| Case | Vuln trigger | Observed effect | Control trigger | Observed effect |
|------|--------------|-----------------|-----------------|-----------------|
| `storeUserToken` | `{storeUserToken: true, token: "attacker-canary-token"}` | `general_token` overwritten to attacker value | `{totallyUnrelatedKey: "hello"}` | `general_token` unchanged |
| `sendRawLog` | `{action: "SEND_RAW_LOG", payload: {type: "YOUTUBE", body: {advert: "attacker-canary-payload"}}}` | `sendRawLog` called with attacker payload | `{totallyUnrelatedKey: "hello"}` | no `sendRawLog` call |

Both cases produced different stdout hashes from their shared control, so the `funnel.py verify` differential gate reported **YES** for each.

### Ledger verification

```
python3 funnel.py verify 120 --vuln 'node ../scratch/wtm-bridge-replay.js --case storeUserToken' --control 'node ../scratch/wtm-bridge-replay.js --case benign'
  [vuln] rc=0 105ms sha=b0b4a42f9a44f189
  [control] rc=0 116ms sha=076674ab5a6ff335
  differential vs control: 1/1 replay pair(s) YES

python3 funnel.py verify 122 --vuln 'node ../scratch/wtm-bridge-replay.js --case sendRawLog' --control 'node ../scratch/wtm-bridge-replay.js --case benign'
  [vuln] rc=0 91ms sha=6092ff9c806dc3f5
  [control] rc=0 103ms sha=076674ab5a6ff335
  differential vs control: 1/1 replay pair(s) YES
```

## Scope and accuracy notes

- The finding is **not** about `externally_connectable`; the extension does not declare it. The vulnerability is the internal content-script bridge.
- The content script is injected on all sites listed in `src/build/site-matches.json` (facebook, x, instagram, youtube, ~200 google TLDs, etc.), so a malicious or compromised ad/script on any of those origins can reach the bridge.
- `SEND_RAW_LOG` and `UPDATE_USER` require the victim to be logged in and non-EU; `storeUserToken`/`deleteWTMUser`/`registerWTMUser` do not.
- This finding overlaps with W2 (`registrationFeedback` token disclosure). W1 is the broader bridge-abuse class; W2 is the specific registration-token leak. They are distinct bugs but share the same ungated bridge.

## Method

- Offline, canary-only (`attacker-canary-token`, `attacker-canary-payload`, `victim-canary-token`); no network egress, no real credentials.
- Real source: repo files executed verbatim via `node:vm` after stripping ESM import/export syntax. No re-implementation of extension logic.
- Mocks encode browser platform guarantees only: `window.addEventListener/message` for page→content-script IPC; `chrome.runtime.sendMessage/onMessage` for content-script→background IPC; extension-private `chrome.storage.local` vs page-origin `localStorage`.
- Differential: attacker-shaped message vs. unrelated benign message. Each run is a fresh process = clean state. 3/3 captured runs for each case.

## Commands

```sh
node scratch/wtm-bridge-replay.js --case storeUserToken
node scratch/wtm-bridge-replay.js --case sendRawLog
node scratch/wtm-bridge-replay.js --case benign
```

## Captured output (×3 each, exit code 0)

`storeUserToken` vuln:

```
general_token after page message: attacker-canary-token
RESULT: OVERWRITTEN by page-controlled message
```

`storeUserToken` control:

```
general_token after benign page message: victim-canary-token
RESULT: unchanged (control)
```

`sendRawLog` vuln:

```
sendRawLog calls: [{"type":"YOUTUBE","body":{"advert":"attacker-canary-payload"}}]
RESULT: page-injected rawlog accepted
```

`sendRawLog` control:

```
general_token after benign page message: victim-canary-token
RESULT: unchanged (control)
```
