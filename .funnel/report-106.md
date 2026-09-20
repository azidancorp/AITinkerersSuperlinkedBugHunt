# Vulnerability report -- candidate #106 [VERIFIED -- differential YES]

- target: vibe-kanban (/home/azidan/AQL/AI/AITinkerers/vibe-kanban)
- registered snapshot HEAD: d5cbb5380fa0b32e98ef9b8d987f63decce4be3a
- generated: 2026-09-20T15:54:50+00:00
- funnel source: variant | verdict: None | confidence: None | stage: verified

## 1. Title
<!-- one sober sentence: class + file:symbol + attacker capability + precondition -->
Origin validation accepts Origin==Host equality against the client-controlled Host header and passes requests with no Origin at all (middleware/origin.rs validate_origin), so DNS rebinding yields full access to the unauthenticated local API incl. terminal PTY and cloud-token endpoint

## 2. Summary
<!-- 3-5 sentences naming the security boundary crossed. No boundary, no finding. -->


## 3. Affected product & version
<!-- repo URL + exact commit hash tested; affected range from git log, never assumed -->
/home/azidan/AQL/AI/AITinkerers/vibe-kanban @ d5cbb5380fa0b32e98ef9b8d987f63decce4be3a (registered snapshot)

## 4. Attacker model & preconditions
<!-- feeds CVSS PR/AT/UI; state non-default config in bold -->


## 5. Proof of concept
<!-- one-command setup on the pinned commit; minimal trigger; deterministic artefact; rerun >=3x from clean -->


## 6. Root cause
<!-- <=10 lines: file:line, short excerpt, source->sink dataflow. If you cannot point at the line, it is not validated -->
crates/server/src/middleware/origin.rs:41

CWE: CWE-346  severity hint: high

validate_origin (crates/server/src/middleware/origin.rs:41-79) is the only auth-style gate applied to api_routes (routes/mod.rs api_routes layer ValidateRequestHeaderLayer::custom(validate_origin); handlers themselves take no auth extractors, e.g. routes/filesystem.rs list_directory and routes/terminal.rs terminal_ws). Two weaknesses observed at HEAD: (1) line 45: requests with no Origin header return Ok — fine for curl but also true for same-origin GET navigations/fetches after DNS rebinding, where the browser omits Origin; (2) lines 59-60 + origin_matches_host (line 113): an Origin that merely equals the Host header is treated as same-origin — under DNS rebinding both Origin and Host are the attacker-controlled domain that re-resolves to 127.0.0.1, so the equality passes. VK_ALLOWED_ORIGINS only ADDS allowed origins, never restricts Host. Impact: a rebound origin reaches /api/filesystem/directory?path= (arbitrary host directory listing, services/filesystem), /api/terminal websocket (PTY in any workspace), /api/auth/token (returns cloud access token), and workspace/session creation that spawns agent executors. Variant of the class introduced by seed 346db013 "verify origin (#2139)" which added this middleware.

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
[{"label": "vuln", "cmd": "sh /home/azidan/AQL/AI/AITinkerers/scratch/verify/vibe-kanban-V2/v2-vuln.sh", "rc": 0, "ms": 31.1, "stdout_sha256": "5b11d8b4a9705a1b", "stdout_len": 376, "stderr_len": 0, "stdout_head": "SHAPE A_NO_ORIGIN status=200 handler_reached=1 verdict=BYPASSED\nSHAPE B_ORIGIN_EQ_HOST status=200 handler_reached=1 verdict=BYPASSED\nSHAPE B2_ORIGIN_EQ_HOST_KEYPATH status=200 handler_reached=1 verdict=BYPASSED\nSHAPE C_RELAY_HEADER_SKIP status=200 handler_reached=1 verdict=BYPASSED\nVULN_EFFECT=observed (4/4 attacker-shaped requests reached the handler past validate_origin)\n", "stderr_head": ""}, {"label": "control", "cmd": "sh /home/azidan/AQL/AI/AITinkerers/scratch/verify/vibe-kanban-V2/v2-control.sh", "rc": 0, "ms": 31.2, "stdout_sha256": "c7a87e3caa64aae6", "stdout_len": 288, "stderr_len": 0, "stdout_head": "SHAPE K1_CROSS_ORIGIN status=403 handler_reached=0 verdict=BLOCKED\nSHAPE K2_NULL_ORIGIN status=403 handler_reached=0 verdict=BLOCKED\nSHAPE K3_CROSS_PORT_REBIND status=403 handler_reached=0 verdict=BLOCKED\nCONTROL_EFFECT=blocked (3/3 control requests rejected by validate_origin with 403)\n", "stderr_head": ""}, {"label": "vuln", "cmd": "sh /home/azidan/AQL/AI/AITinkerers/scratch/verify/vibe-kanban-V2/v2-vuln.sh", "rc": 0, "ms": 29.3, "stdout_sha256": "5b11d8b4a9705a1b", "stdout_len": 376, "stderr_len": 0, "stdout_head": "SHAPE A_NO_ORIGIN status=200 handler_reached=1 verdict=BYPASSED\nSHAPE B_ORIGIN_EQ_HOST status=200 handler_reached=1 verdict=BYPASSED\nSHAPE B2_ORIGIN_EQ_HOST_KEYPATH status=200 handler_reached=1 verdict=BYPASSED\nSHAPE C_RELAY_HEADER_SKIP status=200 handler_reached=1 verdict=BYPASSED\nVULN_EFFECT=observed (4/4 attacker-shaped requests reached the handler past validate_origin)\n", "stderr_head": ""}, {"label": "control", "cmd": "sh /home/azidan/AQL/AI/AITinkerers/scratch/verify/vibe-kanban-V2/v2-control.sh", "rc": 0, "ms": 34.8, "stdout_sha256": "c7a87e3caa64aae6", "stdout_len": 288, "stderr_len": 0, "stdout_head": "SHAPE K1_CROSS_ORIGIN status=403 handler_reached=0 verdict=BLOCKED\nSHAPE K2_NULL_ORIGIN status=403 handler_reached=0 verdict=BLOCKED\nSHAPE K3_CROSS_PORT_REBIND status=403 handler_reached=0 verdict=BLOCKED\nCONTROL_EFFECT=blocked (3/3 control requests rejected by validate_origin with 403)\n", "stderr_head": ""}, {"label": "vuln", "cmd": "sh /home/azidan/AQL/AI/AITinkerers/scratch/verify/vibe-kanban-V2/v2-vuln.sh", "rc": 0, "ms": 29.8, "stdout_sha256": "5b11d8b4a9705a1b", "stdout_len": 376, "stderr_len": 0, "stdout_head": "SHAPE A_NO_ORIGIN status=200 handler_reached=1 verdict=BYPASSED\nSHAPE B_ORIGIN_EQ_HOST status=200 handler_reached=1 verdict=BYPASSED\nSHAPE B2_ORIGIN_EQ_HOST_KEYPATH status=200 handler_reached=1 verdict=BYPASSED\nSHAPE C_RELAY_HEADER_SKIP status=200 handler_reached=1 verdict=BYPASSED\nVULN_EFFECT=observed (4/4 attacker-shaped requests reached the handler past validate_origin)\n", "stderr_head": ""}, {"label": "control", "cmd": "sh /home/azidan/AQL/AI/AITinkerers/scratch/verify/vibe-kanban-V2/v2-control.sh", "rc": 0, "ms": 28.5, "stdout_sha256": "c7a87e3caa64aae6", "stdout_len": 288, "stderr_len": 0, "stdout_head": "SHAPE K1_CROSS_ORIGIN status=403 handler_reached=0 verdict=BLOCKED\nSHAPE K2_NULL_ORIGIN status=403 handler_reached=0 verdict=BLOCKED\nSHAPE K3_CROSS_PORT_REBIND status=403 handler_reached=0 verdict=BLOCKED\nCONTROL_EFFECT=blocked (3/3 control requests rejected by validate_origin with 403)\n", "stderr_head": ""}]
```
