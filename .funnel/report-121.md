# Vulnerability report -- candidate #121 [VERIFIED -- differential YES]

- target: Who-Targets-Me (/home/azidan/AQL/AI/AITinkerers/Who-Targets-Me)
- registered snapshot HEAD: 64e9989c65ba83e8536e57768e19ff0b6409abda
- generated: 2026-09-20T15:52:17+00:00
- funnel source: variant | verdict: None | confidence: None | stage: verified

## 1. Title
registrationFeedback bearer token is written to the active-tab origin localStorage and broadcast with window.postMessage "*", so the fresh general_token leaks to an arbitrary matched site if the user switches tabs during the async registration round-trip

## 2. Summary
The extension's API bearer credential (`general_token`, sent as the `Authorization` header to the WTM data API) crosses from privileged extension storage into an untrusted web-page origin. After a user registers, the background handler sends the fresh token to **whichever tab is focused** (`chrome.tabs.query({active:true, currentWindow:true})`), and the content script running on that page persists it into the **page origin's `localStorage`** and re-broadcasts it with `window.postMessage(request, "*")` — disclosing it to every script on that page, including third-party analytics/ad scripts the page embeds. The boundary crossed is privileged-extension-context → web-origin DOM: a secret that only `chrome.storage.local` should ever hold becomes same-origin-readable (and *persistent* — `localStorage` outlives the page) on facebook.com, x.com, instagram.com, youtube.com and whotargets.me origins. The extension never reads the page copy back (`readStorage` → `chrome.storage.local`), so the copy is pure confidentiality loss with no functional purpose.

## 3. Affected product & version
/home/azidan/AQL/AI/AITinkerers/Who-Targets-Me @ 64e9989c65ba83e8536e57768e19ff0b6409abda (registered snapshot)

Upstream: https://github.com/WhoTargetsMe/Who-Targets-Me.git. Affected range (from git, not assumed): the `registrationFeedback` sink was introduced in `src/daemon/index.js` by commit `3c7244a` (2023-08-29, "feat(WTM-632): Updated FF and other browser handlers") and is unchanged through the tested HEAD `64e9989c65` — every release since 2023-08-29 that ships `daemon/index.js` is affected. Note: `src/contents/index.js:13-17` holds a byte-identical sink but is a dead duplicate — not built by `webpack.daemon.config.js` and not referenced by either manifest template. The **live** sink is `src/daemon/index.js` (both v2 and v3 manifests: `content_scripts.js = ["daemon/index.js"]`).

## 4. Attacker model & preconditions
- **Victim**: any Who-Targets-Me user who registers an account (default flow; no non-default configuration is involved — **all** browsers ship this path: the `callback()` switch covers `chrome`, `edge` and `firefox` identically, `onMessageEventHandler.js:24-33`).
- **Attacker**: any JavaScript already running in — or later loaded into — the page origin of whatever tab is focused when the async `createUserCredentials` response resolves. Realistic instantiations: third-party/analytics/ad scripts embedded by the matched platforms themselves, a compromised embedded script, or script injected by any other flaw on those origins. **PR:N** (no privileges; being a script on the page is sufficient) — attacker must *exist* on a matched origin (**AT:P**: preparation required; the matched-origin set is facebook.com, x.com, instagram.com, youtube.com, whotargets.me subdomains, localhost).
- **Trigger**: registration completes while such a tab is the active tab in the current window (`postMessageToFirstActiveTab.js:3-4` queries *at callback time* — the initiating tab is not tracked). **UI:A** (user performs the registration interaction; nothing further).
- **Exposure window is unbounded**: the token persists in that origin's `localStorage` indefinitely, so scripts that only run on the origin *later* (subsequent visits, future embedded vendors) can still read it. The `postMessage("*")` broadcast is an additional immediate disclosure to all listeners, including cross-origin iframes that share the window (the `*` target origin places no restriction).

## 5. Proof of concept
One-command setup on the pinned commit (offline, no browser, no extension install; Node ≥ 18):

```sh
# from the workspace root (repo pinned at 64e9989c65, git status clean)
node scratch/wtm-bridge-replay.js --case feedback          # vuln
node scratch/wtm-bridge-replay.js --case feedback-benign   # control
```

The harness loads the **actual HEAD source** (`src/daemon/index.js` + `src/shared/handlers/onMessageEventHandler.js`) into a `node:vm` sandbox with only the browser platform mocked (`chrome.tabs`, `chrome.runtime`, `window`, `localStorage`). It simulates the background's post-registration callback delivering `{registrationFeedback: {token: "fresh-canary-token"}}` to the content script (synthetic canary; no real credential, no network).

Deterministic artefacts (vuln run, exit 0, ~70 ms):

```
page localStorage: {"general_token":"\"fresh-canary-token\""}
page postMessage log: [{"registrationFeedback":{"token":"fresh-canary-token"}}]
RESULT: bearer token written to page-origin localStorage and broadcast
```

Control run (same listener, benign message `{}`): `page localStorage: {}` / `RESULT: nothing written (control)`.

Rerun from clean: the formal gate replayed the pair **3/3 times from fresh sandboxes** (sub-second each; satisfies the five-minute rule). Differential mechanism: the *only* variable is the presence of the `registrationFeedback` field — the sink writes and broadcasts iff the token-carrying message arrives.

## 6. Root cause
src/daemon/index.js:15

CWE: CWE-200  severity hint: high

Observed at HEAD: after registration the background sends {registrationFeedback: response} (response contains the new token, src/shared/handlers/handleUserRegistration.js:11-13) via postMessageToFirstActiveTab (src/shared/utils/postMessageToFirstActiveTab.js:3-6: chrome.tabs.query({active:true,currentWindow:true}) then tabs[0] -- whatever tab happens to be active when the async createUserCredentials response arrives, not necessarily the tab that initiated registration). The content-script listener src/daemon/index.js:13-17 then does localStorage.setItem("general_token", JSON.stringify(request.registrationFeedback.token)) on that page origin and window.postMessage(request, "*") broadcasting the token to every script in that page. All site-matches.json origins (facebook.com, x.com, instagram.com, youtube.com, whotargets.me subdomains, localhost) run this listener. Offline replay harness (vm-sandboxed actual HEAD daemon/index.js) shows the canary token landing in page-origin localStorage and in the page postMessage log. Same dead-code duplicate exists in src/contents/index.js:13-17 (not built by webpack.daemon.config.js).

Dataflow (4 hops): `handleUserRegistration` stores token in `chrome.storage.local` (correct) **and** invokes `responseCallback(response)` → `onMessageEventHandler.js:28` `postMessageToFirstActiveTab({registrationFeedback: response})` → `postMessageToFirstActiveTab.js:3-4` resolves the *currently focused* tab and `tabs.sendMessage` → `daemon/index.js:15-16` writes the token into **page** `localStorage` + `window.postMessage(request, "*")`.

## 7. Impact
**Demonstrated (replay, 3/3)**: a fresh, valid API bearer credential is (a) persisted into the page-origin `localStorage` of the active matched-site tab and (b) broadcast to every message listener in that page, with no target-origin restriction. By browser platform guarantee (not extension code), every same-origin script — and any script the page later loads on that origin — can read `localStorage.getItem("general_token")` or subscribe to `message` events. The token is the account credential: `src/shared/api/app.js:9-13` uses it as the `Authorization` header for all data-API calls (`DATA_API_URL`), including rawlog submission. The extension never reads the page copy back (`readStorage` → `chrome.storage.local`), so this is pure credential disclosure with zero functional value.

**Potential but NOT demonstrated (unverified hypotheses)**: hostile use of the stolen token against the API (forged rawlog submission as the victim, account read/deletion — the exact API scope of a `general_token` was not enumerated offline); exploitation requires an attacker-controlled or compromised script on a matched origin *or* any future one, since the copy persists. No integrity or availability impact on the extension itself was observed. In line with the workspace's honest-scoring rule, only the disclosure is scored.

## 8. Severity (CVSS v4.0)
`CVSS:4.0/AV:N/AC:L/AT:P/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` (computed hint, ~5.9 Medium–High boundary; human review applies)

- **AV:N** — the attacker is a network-loaded script in the victim's page; no local access needed.
- **PR:N** — any script on the page origin qualifies; no platform or extension privilege required.
- **AT:P** — preparation: the attacker must have script presence on a *matched* origin (or rely on the persistent `localStorage` copy and arrive later).
- **UI:A** — the victim must complete the registration flow; no further interaction.
- **VC:H** — full compromise of the confidentiality of the account credential; **VI:N/VA:N** — no demonstrated integrity/availability effect (read-only disclosure); **SC/SI/SA:N** — no demonstrated impact beyond the single extension account.

## 9. Suggested fix
The token already lives in `chrome.storage.local` (`handleUserRegistration.js:11`) — the page copy is redundant, so the simplest fix is to **delete `daemon/index.js:15`** (the `localStorage.setItem`) and strip the secret before rebroadcasting: send only a non-secret acknowledgement, e.g. `window.postMessage({ registrationFeedback: { ok: true } }, location.origin)` — replacing `"*"` with the page's own origin so no other embedded context receives it. If the page-side UI genuinely needs to know registration succeeded, that boolean suffices; no handler in the repo reads the broadcast token back.

## 10. Evidence attachments
- Replay harness (loads real HEAD source, canary-only, offline): `scratch/wtm-bridge-replay.js` (cases `feedback` / `feedback-benign`).
- Gate record: replay log appended below (6 runs, stdout SHA-16 `eed045734e4b59cc` vuln vs `7a0c19182995fdd0` control, both rc=0).
- Worksheet with method and honest-scoping notes: `scratch/verify/Who-Targets-Me-W2/worksheet.md`.
- Independent-replication brief for a second reviewer: `scratch/verify/Who-Targets-Me-W2/replication-prompt.md`.
- All tokens in evidence are synthetic canaries (`fresh-canary-token`); no real credentials, no network egress.

## 11. Verification & retest
Clean-environment reproductions: **3/3 differential YES** on 2026-09-20 via `python3 funnel.py verify 121 --repeat 3` (each run constructs a fresh `node:vm` sandbox and fresh mock storage; nothing persists between runs). Retest: re-run the two commands in field 5 on the pinned commit and compare against the artefacts in field 5. Expected secure output after the field-9 patch: vuln and control runs become byte-identical (`general_token` never written, no token in any broadcast) — i.e. the differential disappears, which is the gate's definition of fixed.

## 12. AI-use disclosure
Finding identified by an AI-assisted variant-analysis lane and registered as ledger candidate #121 (dup: #102). Replay harness authored and executed by an AI agent against the unmodified pinned snapshot; the differential gate (`funnel.py verify`) is deterministic stdlib-only tooling that measures outputs rather than trusting the model's claims. Human review of this report is required before any external submission; all evidence uses synthetic canary credentials.

## 13. Disclosure commitments
Per the hackathon workspace rules, **no contact with maintainers or the repo community occurs during the event** (no issues, PRs, comments or emails). If this finding is released afterwards: private report to WhoTargetsMe first, 90-day default embargo from acknowledgement, a retest offer before any publication, and coordinated publication thereafter. Reference ID: funnel candidate #121 (alias W2). Contact via the submitting team only.

## 14. Scope & safety statement
All testing was performed offline against the approved, pinned, read-only snapshot `Who-Targets-Me/ @ 64e9989c65` in this workspace. No third-party host was contacted; no extension was installed in a live browser; no real user account or credential exists anywhere in the pipeline — every token is a synthetic canary. The replay executes repository-derived code only inside a `node:vm` sandbox with network-free mocks, and repository content is treated as untrusted data at all times.


## Replay record (verify)

```json
[{"label": "vuln", "cmd": "node ../scratch/wtm-bridge-replay.js --case feedback", "rc": 0, "ms": 69.5, "stdout_sha256": "eed045734e4b59cc", "stdout_len": 213, "stderr_len": 0, "stdout_head": "page localStorage: {\"general_token\":\"\\\"fresh-canary-token\\\"\"}\npage postMessage log: [{\"registrationFeedback\":{\"token\":\"fresh-canary-token\"}}]\nRESULT: bearer token written to page-origin localStorage and broadcast\n", "stderr_head": ""}, {"label": "control", "cmd": "node ../scratch/wtm-bridge-replay.js --case feedback-benign", "rc": 0, "ms": 70.6, "stdout_sha256": "7a0c19182995fdd0", "stdout_len": 56, "stderr_len": 0, "stdout_head": "page localStorage: {}\nRESULT: nothing written (control)\n", "stderr_head": ""}, {"label": "vuln", "cmd": "node ../scratch/wtm-bridge-replay.js --case feedback", "rc": 0, "ms": 75.3, "stdout_sha256": "eed045734e4b59cc", "stdout_len": 213, "stderr_len": 0, "stdout_head": "page localStorage: {\"general_token\":\"\\\"fresh-canary-token\\\"\"}\npage postMessage log: [{\"registrationFeedback\":{\"token\":\"fresh-canary-token\"}}]\nRESULT: bearer token written to page-origin localStorage and broadcast\n", "stderr_head": ""}, {"label": "control", "cmd": "node ../scratch/wtm-bridge-replay.js --case feedback-benign", "rc": 0, "ms": 69.0, "stdout_sha256": "7a0c19182995fdd0", "stdout_len": 56, "stderr_len": 0, "stdout_head": "page localStorage: {}\nRESULT: nothing written (control)\n", "stderr_head": ""}, {"label": "vuln", "cmd": "node ../scratch/wtm-bridge-replay.js --case feedback", "rc": 0, "ms": 77.1, "stdout_sha256": "eed045734e4b59cc", "stdout_len": 213, "stderr_len": 0, "stdout_head": "page localStorage: {\"general_token\":\"\\\"fresh-canary-token\\\"\"}\npage postMessage log: [{\"registrationFeedback\":{\"token\":\"fresh-canary-token\"}}]\nRESULT: bearer token written to page-origin localStorage and broadcast\n", "stderr_head": ""}, {"label": "control", "cmd": "node ../scratch/wtm-bridge-replay.js --case feedback-benign", "rc": 0, "ms": 69.5, "stdout_sha256": "7a0c19182995fdd0", "stdout_len": 56, "stderr_len": 0, "stdout_head": "page localStorage: {}\nRESULT: nothing written (control)\n", "stderr_head": ""}]
```
