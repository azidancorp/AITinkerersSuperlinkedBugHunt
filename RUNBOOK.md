# Day-of runbook (no pre-built pipeline; T-1h)

## Terminal 0 -- network first
Test venue wifi now. Phone hotspot ready on a SECOND carrier.
LLM credentials: export LLM_BASE_URL / LLM_API_KEY / LLM_MODEL before anything else.
If no API key: pip install semgrep, use `mine` + manual `add`; triage waits for a key.

## T-0:15 -- targets announced
    python3 funnel.py init <url-or-path> p1
    python3 funnel.py init <url-or-path> p2
    python3 funnel.py init <url-or-path> p3
Run one egress sanity check: nothing in the pipeline touches a third-party host.
Targets only, canaries only, no real credentials. That is the DQ insurance.

## T+0:00 -- fire the instant lanes (all three, parallel)
    python3 funnel.py mine p1 ; python3 funnel.py mine p2 ; python3 funnel.py mine p3
    python3 funnel.py sweep p1  (semgrep; noisy by design)
`mine` output IS your worklist: upstream-gap seeds are near-certain bugs in the
snapshot; churn-A seeds are fix-commits on hot files. Feed each top seed to an
agent with `git show <sha>` +: "This was a previous bug; there is probably
another similar one somewhere." Review HEAD for related unfixed issues.
Second prompt per seed: "Here is a fix commit. Assume it is incomplete. Find
inputs or paths where the fixed behaviour still fails."

## T+0:30 -- fuzz only if cheap
Enrolled in OSS-Fuzz -> helper.py build_fuzzers --sanitizer=address (~15 min).
Python + C extension -> atheris + LD_PRELOAD asan. JVM -> cifuzz/jazzer-autofuzz.
Not building within 30 min -> drop the target, move on. No harness surgery.
Any crash: `add` with --cmd-vuln 'run crash input' --cmd-control 'run benign input'.

## Every finding, without exception
    python3 funnel.py add p1 --title "..." --file ... --line ... --severity ... --cwe ...
    python3 funnel.py verify N --vuln '<replay>' --control '<benign replay>'
Differential NO -> it is not a finding. That is the gate. Do not negotiate it.

## Hourly
    python3 funnel.py stats
Watch candidate->tp ratio, not tokens. If zero tp by T+2:00, drop to the single
best-converting target and feed the agent crash traces + sanitizer output.

## T+4:30 -- freeze
No new capabilities. Only: verification, `report <id>`, replay-from-clean runs.
Re-verify top findings on a second machine/environment if one exists.

## T+6:00 -- submit
Fill all 14 fields of each report. Replay each one from clean. Synthetic
fixtures only. Nothing unverified ships. A wrong submission scores zero; a
missing one scores the same but costs no credibility.
