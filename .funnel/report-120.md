# Vulnerability report -- candidate #120 [VERIFIED -- differential YES]

- target: Who-Targets-Me (/home/azidan/AQL/AI/AITinkerers/Who-Targets-Me)
- registered snapshot HEAD: 64e9989c65ba83e8536e57768e19ff0b6409abda
- generated: 2026-09-20T16:17:22+00:00
- funnel source: variant | verdict: None | confidence: None | stage: verified

## 1. Title
<!-- one sober sentence: class + file:symbol + attacker capability + precondition -->
Missing origin/sender validation on page-to-background bridge: any script on a matched site (facebook/instagram/x/youtube/*.whotargets.me/localhost/google.*) can window.postMessage {storeUserToken} and overwrite the general_token bearer credential in extension storage

## 2. Summary
<!-- 3-5 sentences naming the security boundary crossed. No boundary, no finding. -->


## 3. Affected product & version
<!-- repo URL + exact commit hash tested; affected range from git log, never assumed -->
/home/azidan/AQL/AI/AITinkerers/Who-Targets-Me @ 64e9989c65ba83e8536e57768e19ff0b6409abda (registered snapshot)

## 4. Attacker model & preconditions
<!-- feeds CVSS PR/AT/UI; state non-default config in bold -->


## 5. Proof of concept
<!-- one-command setup on the pinned commit; minimal trigger; deterministic artefact; rerun >=3x from clean -->


## 6. Root cause
<!-- <=10 lines: file:line, short excerpt, source->sink dataflow. If you cannot point at the line, it is not validated -->
src/daemon/index.js:10

CWE: CWE-346  severity hint: high

Observed at HEAD: content script src/daemon/index.js:5-11 forwards every window message (only check is event.source==window, trivially satisfied by any page-world script) verbatim via chrome.runtime.sendMessage. Background src/shared/handlers/onMessageEventHandler.js:14-21 ignores the sender argument entirely; handleOtherRequests (lines 36-58) requires no login: storeUserToken -> setToStorage("general_token", request.token) (line 56), deleteWTMUser -> wipes credentials (line 53-54), registerWTMUser -> attacker-controlled registration + chrome.runtime.reload() (lines 38-46). general_token is the sole auth credential, sent as the Authorization header on every DATA_API call (src/shared/api/app.js:9-13). Content script is injected on all sites in src/build/site-matches.json (webpack.daemon.config.js:34), incl. *.facebook.com, *.x.com, *.instagram.com, *.youtube.com, *.whotargets.me, localhost, ~200 google domains. Offline replay harness (scratch/wtm-bridge-replay.js, vm-sandboxed actual HEAD sources, mocked chrome APIs) shows a synthetic page message overwriting general_token while an unrelated message leaves it intact.

## 7. Impact
<!-- demonstrated vs potential. Score only what the PoC showed; label escalation as unverified hypothesis -->


## 8. Severity (CVSS v4.0)
<!-- full vector string; justify PR, UI, SC/SI/SA explicitly -->


## 9. Suggested fix
<!-- 1-3 sentences or a candidate patch diff; an 80% patch is still valuable -->


## 10. Evidence attachments
<!-- PoC bundle, terminal capture, raw request/response pairs; text over video; synthetic fixtures only -->


## 11. Verification & retest
<!-- number of clean-environment reproductions with dates; expected secure output after patch -->


## 12. AI-use disclosure
<!-- mandatory: AI-assisted identification + human reproduction, minimisation and verification -->


## 13. Disclosure commitments
<!-- private report, 90-day default embargo, follow-up window, retest offer, contact + reference ID -->


## 14. Scope & safety statement
<!-- isolated self-hosted targets only; no third-party infrastructure; no real credentials; synthetic canaries only -->


## Replay record (verify)

```json
[{"label": "vuln", "cmd": "node ../scratch/wtm-bridge-replay.js --case storeUserToken", "rc": 0, "ms": 105.0, "stdout_sha256": "b0b4a42f9a44f189", "stdout_len": 103, "stderr_len": 0, "stdout_head": "general_token after page message: attacker-canary-token\nRESULT: OVERWRITTEN by page-controlled message\n", "stderr_head": ""}, {"label": "control", "cmd": "node ../scratch/wtm-bridge-replay.js --case benign", "rc": 0, "ms": 116.4, "stdout_sha256": "076674ab5a6ff335", "stdout_len": 89, "stderr_len": 0, "stdout_head": "general_token after benign page message: victim-canary-token\nRESULT: unchanged (control)\n", "stderr_head": ""}]
```
