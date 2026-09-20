# Who-Targets-Me W2 — ledger #121 — registrationFeedback token disclosure (VERIFIED)

Status: candidate #121, **differential gate YES 3/3** (2026-09-20). Dup: #102
(same finding, registered first, no cmd pair — #121 is canonical for the gate).
Origin: variant lane; also probed by WTM review #2 and semgrep tp #10/#11
(`postMessage "*"` sink).
HEAD: `64e9989c65` (pinned snapshot, unmodified; `git status --porcelain` empty).
Report: `.funnel/report-121.md` (all 14 fields filled).

## The finding

After registration the background handler delivers the fresh account bearer
token to the **content script of whichever tab is focused at callback time**
(`src/shared/utils/postMessageToFirstActiveTab.js:3-4`:
`chrome.tabs.query({active:true, currentWindow:true})` — the initiating tab is
not tracked). The live content script (`src/daemon/index.js:13-17`, confirmed
live: both v2 and v3 manifests pin `content_scripts.js = ["daemon/index.js"]`)
then:

1. `localStorage.setItem("general_token", JSON.stringify(token))` — writes the
   credential into the **page origin's** storage (shared with and persistent
   for every script on that origin), and
2. `window.postMessage(request, "*")` — broadcasts the token to every message
   listener in the page, no target-origin restriction.

The token is the API credential: `src/shared/api/app.js:9-13` sends it as the
`Authorization` header to `DATA_API_URL` (rawlog submission et al.). The
extension never reads the page copy back (`readStorage` → `chrome.storage.local`
only), so the disclosure has zero functional purpose — pure confidentiality
loss. Exposure set: the `site-matches.json` origins (facebook.com, x.com,
instagram.com, youtube.com, whotargets.me subdomains, localhost) — scope claims
to "matched origins", never "any origin".

Affected range (git): sink introduced by `3c7244a` (2023-08-29), unchanged
through HEAD. `src/contents/index.js:13-17` is a byte-identical **dead
duplicate** (not built by `webpack.daemon.config.js`) — do not gate on it.

## Differential replay

Harness: `scratch/wtm-bridge-replay.js` (workspace scratch) — loads the actual
HEAD `src/daemon/index.js` + `src/shared/handlers/onMessageEventHandler.js`
into a `node:vm` sandbox (imports stripped, `chrome.tabs`/`chrome.runtime`/
`window`/`localStorage` mocked, synthetic canaries only, no network). Same
technique as the two prior WTM verifications (#131/W5a, #132/W8).

```
vuln:    node ../scratch/wtm-bridge-replay.js --case feedback
           page localStorage: {"general_token":"\"fresh-canary-token\""}
           page postMessage log: [{"registrationFeedback":{"token":"fresh-canary-token"}}]
           RESULT: bearer token written to page-origin localStorage and broadcast
control: node ../scratch/wtm-bridge-replay.js --case feedback-benign
           page localStorage: {}
           RESULT: nothing written (control)
gate:    python3 funnel.py verify 121 --repeat 3 --vuln ... --control ...
           differential vs control: 3/3 replay pair(s) YES   (stage -> verified)
```

The only variable is the presence of the `registrationFeedback` field on the
runtime message; the sink writes+broadcasts iff the token-carrying message
arrives. Mock fidelity is a platform guarantee, not extension behaviour: a
content script's `localStorage` *is* the page origin's storage, and
`postMessage(msg, "*")` *is* delivered to every listener regardless of origin.

## Honest severity note

Demonstrated: fresh valid bearer credential persisted to page-origin
localStorage + broadcast to all page listeners (3/3 clean replays). NOT
demonstrated: hostile exfiltration by a real embedded script (platform
guarantee instead), and any backend effect of the stolen token (API scope not
enumerated offline). Score the disclosure, not the takeover — same posture as
W8's "backend acceptance NOT demonstrated".

## Harness caveat on record

`scratch/wtm-verify/c115-vuln.mjs` / `c115-control.mjs` (earlier lane) import
`src/contents/index.js` — the dead duplicate. The gate and this worksheet use
only the live sink (`src/daemon/index.js`). If c115 is ever re-run, treat it as
testing the duplicate, not the shipped extension.
