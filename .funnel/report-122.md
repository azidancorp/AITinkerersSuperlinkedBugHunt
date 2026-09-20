# Vulnerability report -- candidate #122 [VERIFIED -- differential YES]

- target: Who-Targets-Me (/home/azidan/AQL/AI/AITinkerers/Who-Targets-Me)
- registered snapshot HEAD: 64e9989c65ba83e8536e57768e19ff0b6409abda
- generated: 2026-09-20T16:17:23+00:00
- funnel source: variant | verdict: None | confidence: None | stage: verified

## 1. Title
<!-- one sober sentence: class + file:symbol + attacker capability + precondition -->
SEND_RAW_LOG action accepted from page-controlled postMessage bridge: any script on a matched site can inject forged ad rawlogs into the WTM submit-rawlogs dataset under the victim identity when the user is logged in

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
src/shared/handlers/onMessageEventHandler.js:76

CWE: CWE-345  severity hint: med

Observed at HEAD: src/daemon/index.js:5-11 forwards any same-window postMessage to chrome.runtime.sendMessage with no origin/shape validation; onMessageEventHandler.js:60-85 gates actions only on user.isLoggedIn and non-EU country, never on sender. action "SEND_RAW_LOG" (lines 75-77) calls sendRawLog(payload) which posts attacker-supplied body to the submit-rawlogs service (src/shared/api/sendRawLog.js:11-21) with the victim general_token; the only filter is hasConsentedForPlatform(rawlog.type), and the attacker chooses type from {facebook,youtube,twitter,instagram}. Same bridge reaches UPDATE_USER (line 78-80, overwrites stored consent/platforms via user.update) and CONSENT_SET_ASK_ME_LATER_DATE (81-84). Replay harness against actual HEAD sources shows a synthetic page postMessage accepted as a rawlog. Preconditions: victim registered/logged in, non-EU userCountry.

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
[{"label": "vuln", "cmd": "node ../scratch/wtm-bridge-replay.js --case sendRawLog", "rc": 0, "ms": 90.7, "stdout_sha256": "6092ff9c806dc3f5", "stdout_len": 121, "stderr_len": 0, "stdout_head": "sendRawLog calls: [{\"type\":\"YOUTUBE\",\"body\":{\"advert\":\"attacker-canary-payload\"}}]\nRESULT: page-injected rawlog accepted\n", "stderr_head": ""}, {"label": "control", "cmd": "node ../scratch/wtm-bridge-replay.js --case benign", "rc": 0, "ms": 103.4, "stdout_sha256": "076674ab5a6ff335", "stdout_len": 89, "stderr_len": 0, "stdout_head": "general_token after benign page message: victim-canary-token\nRESULT: unchanged (control)\n", "stderr_head": ""}]
```
