# Snare production-risk review — incomplete

Date: 2026-09-20
Repository: /home/azidan/AQL/AI/AITinkerers/snare
Reviewed commit: 6d86d72e75a6 (working tree was clean during inspection)

The user requested a review of consequential production bugs, excluding minor issues. Work stopped at the user's request. The observations below are source-based candidates, not reproduced or confirmed vulnerabilities. No project source files were changed and no fixes were implemented.

## Findings requiring verification

### 1. Unbounded HTTP request lines and headers

Location: src/httpserver.rs, parse_get(), approximately lines 324–380.

The parser uses read_line() into growable strings for the request line and each header. It accumulates headers without a line-size, total-byte, or header-count limit. MAX_HTTP_BODY_SIZE limits only the body, after headers have already been read. This processing occurs before webhook authentication.

Potential consequence: a client able to reach the listener can consume arbitrarily increasing memory through request metadata, potentially exhausting the daemon's memory. A reverse proxy that enforces suitable limits may reduce exposure.

Suggested correction: enforce request-line, per-header, total-header, and header-count limits while reading, before allocating beyond those limits.

Verification status: source inspection only. A bounded 24 MiB header probe was prepared, but the test server did not publish its readiness information and the harness exited before sending any request. No memory-exhaustion effect was measured.

### 2. Per-read timeout permits slow clients to occupy all HTTP workers

Location: src/httpserver.rs, serve(), request(), and parse_get(); NET_TIMEOUT is defined near line 26, and socket timeouts are set near line 156.

The socket timeout limits individual blocking reads. There is no overall request deadline. A client can potentially keep a request incomplete by sending data more frequently than the ten-second read timeout. The listener waits when the active-worker limit is reached. The current comparison permits 17 active workers despite the nominal limit of 16; the consequential concern is indefinite occupancy, rather than that off-by-one difference.

Potential consequence: a small number of unauthenticated clients can occupy all HTTP workers and prevent legitimate webhooks from being processed. Reverse-proxy request deadlines and buffering may reduce exposure.

Suggested correction: impose an overall request/header deadline in addition to idle read timeouts, and avoid letting occupied workers indefinitely block admission of legitimate traffic.

Verification status: source inspection only. A local slow-client probe and benign control were prepared but never executed.

### 3. Job timeouts do not reliably release job slots

Location: src/jobrunner.rs, attend(), particularly lines 216–233; also the poll-timeout calculation earlier in attend().

Once a job expires, the runner repeatedly sends SIGTERM to the immediate child PID. It does not terminate a job process group or escalate to SIGKILL. It only checks/reaps the child after both captured output pipes have closed. Descendants can retain those pipes after the shell has terminated, while a child that ignores SIGTERM can also remain alive. The expired deadline makes subsequent poll() calls use a zero timeout.

Potential consequence: a hung job can retain a job slot beyond its configured timeout and cause the runner to consume CPU in a busy loop. Enough such jobs can block all further execution. This requires a problematic configured command or its descendants; an unauthenticated remote trigger was not established. The manual promises SIGTERM delivery, so the concern is the resulting resource retention and polling behaviour, not merely the lack of a documented hard-kill guarantee.

Suggested correction: supervise a job process group, use bounded termination and escalation, reap the immediate child independently of pipe closure, and prevent expired jobs from creating a permanent zero-timeout polling loop.

Verification status: source inspection only. A one-second timeout probe with a longer-lived descendant and a queued follow-up job was prepared but never executed.

### 4. Unix socket listener cannot recover automatically from a leftover socket path

Location: src/httpserver.rs, Listener::bind(), line 40; daemon shutdown/lifecycle handling in src/main.rs.

Unix socket mode calls UnixListener::bind(path) directly. No socket-path removal or stale-socket recovery was found. Closing a Unix listener does not remove its filesystem entry, so a subsequent start using the same path can fail with address-in-use. The serve() error is unwrapped in main().

Potential consequence: deployments using Unix sockets can remain unavailable after an ordinary service stop/restart or crash unless an external service manager or operator removes the stale path. TCP deployments are not affected by this particular issue.

Suggested correction: define socket lifecycle ownership and safely recover stale sockets without deleting an active listener's socket or unrelated filesystem entries; arrange shutdown cleanup where possible.

Verification status: source inspection only. A restart probe, with explicit socket removal as the benign control, was prepared but never executed.

## Completed checks and limits

- Inspected the HTTP listener/parser, HMAC authentication flow, configuration, job runner, queue, startup/privilege-switching code, documentation, and tests.
- Ran the existing suite with the locally installed Rust 1.97.1 toolchain, Cargo offline mode, and an external target directory: 27 tests passed.
- Built an _internal_testing binary after the attempted harness run failed its readiness check. No subsequent probes were run.
- Checked that an isolated user/network namespace could be created with loopback enabled and no external route.
- The failed harness launched a test daemon in that isolated namespace. Its explicitly identified test process group was terminated afterwards.
- No external servers were contacted, no real credentials were used, and no project source changes or commits were made.
- No dependency vulnerability assessment or complete security assurance was established. This review is incomplete.

## Artifacts and extra workflow activity

The parent workspace's AGENTS.md prescribed a candidate ledger workflow. Following that workflow exceeded the focused review the user wanted. The local target was registered as snare and four unverified candidates were added to .funnel/funnel.db via the workspace CLI:

- #111: Unbounded unauthenticated HTTP headers consume arbitrary memory.
- #112: Per-read timeout permits unauthenticated exhaustion of all HTTP workers.
- #113: Job timeout leaves descendants alive and blocks subsequent jobs.
- #114: Unix socket listener cannot restart after normal termination.

These entries remain candidates, not verified findings; their titles and high-severity labels are provisional. No verify or submit command was run for them.

Existing review artifacts:

- scratch/snare-review-20260920/probe.py — prepared local harness; only the failed header-probe startup was attempted.
- /tmp/snare-review-build — external Cargo build/test artifacts.
- scratch/snare-review-20260920/review.md — this note.

No further testing, fixes, ledger changes, or cleanup is being performed following the user's instruction to document the findings and stop.
