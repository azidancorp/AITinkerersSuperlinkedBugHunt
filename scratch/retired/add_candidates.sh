#!/bin/bash
# Persist the 17 variant-analysis candidates from the seed-review swarm to the ledger.
set -e
cd "$(dirname "$0")/.."
add() { python3 funnel.py add "$@"; }

add snare --title 'HTTP request smuggling: duplicate Content-Length last-wins, TE ignored, obs-fold honoured' --file src/httpserver.rs --line 362 --severity high --cwe CWE-444 --source variant
add snare --title 'Unbounded header-line size: memory-exhaustion DoS' --file src/httpserver.rs --line 329 --severity medium --cwe CWE-400 --source variant
add snare --title 'Job timeout enforcement is SIGTERM-only, no SIGKILL escalation' --file src/jobrunner.rs --line 216 --severity medium --cwe CWE-400 --source variant
add snare --title 'Unix socket created with 0777-and-umask permissions, never chmod; stale path blocks restart' --file src/httpserver.rs --line 37 --severity medium --cwe CWE-732 --source variant
add snare --title 'Unauthenticated requests enqueue into unbounded queue when repo has no secret' --file src/httpserver.rs --line 277 --severity high --cwe CWE-770 --source variant

add pizauth --title 'Reserved OAuth param guard bypassable via query string in auth_uri' --file src/config.rs --line 316 --severity high --cwe CWE-20 --source variant
add pizauth --title 'Token dump encryption uses hardcoded published ChaCha20 key' --file src/server/state.rs --line 39 --severity high --cwe CWE-321 --source variant
add pizauth --title 'Control socket: no peer-credential check, socket perms left to umask' --file src/server/mod.rs --line 444 --severity medium --cwe CWE-306 --source variant
add pizauth --title 'Unbounded read_to_end on control socket: memory-exhaustion DoS' --file src/server/mod.rs --line 89 --severity medium --cwe CWE-400 --source variant

add vibe-kanban --title 'Quadratic stdout/ACP log normalizers unfixed sibling of merged DoS fix' --file crates/executors/src/executors/cursor.rs --line 395 --severity high --cwe CWE-400 --source variant
add vibe-kanban --title 'ready_chunks 1024 cap leaves replay superlinear for many-chunk transcripts' --file crates/utils/src/msg_store.rs --line 161 --severity medium --cwe CWE-400 --source variant
add vibe-kanban --title 'GitHub App installation token exposed in git clone argv' --file crates/remote/src/github_app/service.rs --line 291 --severity medium --cwe CWE-214 --source variant

add who-targets-me --title 'Any page script can drive privileged extension actions: no sender check on messages' --file src/shared/handlers/onMessageEventHandler.js --line 14 --severity high --cwe CWE-346 --source variant
add who-targets-me --title 'Registration token written to page-origin localStorage and broadcast via postMessage star' --file src/contents/index.js --line 13 --severity high --cwe CWE-312 --source variant
add who-targets-me --title 'YouTube rawlog context leaks full URL including search_query' --file src/daemon/collector/platforms/youtube/getAdvertContext.js --line 7 --severity high --cwe CWE-598 --source variant
add who-targets-me --title 'EU rawlog pause never engages for tokenless users: TypeError crash' --file src/shared/handlers/handleUserCountry.js --line 5 --severity medium --cwe CWE-754 --source variant
add who-targets-me --title 'getPlatform domain match lacks dot boundary: eviltwitter.com matches' --file src/daemon/collector/platforms/platforms.js --line 17 --severity low --cwe CWE-20 --source variant

python3 funnel.py stats
