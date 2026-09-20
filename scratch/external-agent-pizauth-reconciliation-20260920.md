# External-agent pizauth report — reconciliation, 2026-09-20

Input: an external agent's production-readiness audit of pizauth (upstream
master via raw.githubusercontent.com). Treated as untrusted input per workspace
posture; every factual leg re-verified against our pinned snapshot
(HEAD 6225ea327f) before anything entered the ledger.

Headline answers:

- **Are any of its claims vulnerabilities?** One new real finding: the rustls
  dependency pin (RUSTSEC-2026-0285). The DoS family it describes is real vuln
  content but we had already found it. The rest are documented design
  decisions / hardening gaps, not vulns under the project threat model.
- **Had we already found the ones that are?** Yes for all except the rustls
  pin, which was in neither ledger. It is now candidate #127, differential
  gate YES. Three of its "High" claims matched our session-1 variant-lane
  candidates that were pending restoration; restored as #126/#128/#129/#130.

## Claim-by-claim disposition

| External claim | Verified in snapshot? | Disposition | Ledger |
|---|---|---|---|
| rustls 0.23.43 in Cargo.lock, RUSTSEC-2026-0285 affected (<0.23.45, patched 0.23.45) | Yes: lockfile pins 0.23.43; advisory + range confirmed on rustsec.org (operator lookup, 2026-09-20); direct dep (Cargo.toml:42) used by https callback listener + ureq outbound | **Real, new finding** (supply-chain, CWE-1104). Advisory text tempers it: transcript stays authenticated; effect = peer plaintext handshake messages not rejected. External's "Blocker" grading is production-policy, not exploitability | **#127, verified (differential YES)** |
| Same-UID Unix socket = show/dump/reload/revoke/shutdown | Accurate description | Documented threat model (0700 runtime dir; same-UID is trusted), not a vuln. Hardening angle already ours: umask-dependent perms, no peer-cred check | restored **#130** |
| `pizauth dump` hardcoded ChaCha20 key | Yes: `CHACHA20_KEY` const state.rs:39, comment says anti-grep only | Known, documented limitation — external agent says so himself | restored **#129** |
| Plaintext `client_secret`, no config mode check | Mechanically true | Config-is-trusted design: config control already gives arbitrary shell exec by design (`shell_cmd.rs`). Subsumed; same reasoning as our semgrep CI-pin FPs (#1–4) | not added (by design) |
| `http://` accepted for auth_uri/token_uri | Yes: `check_not_assigned_uri` config.rs:333 | Config-controlled; same subsumption as above | not added (by design) |
| DoS: unbounded threads, `read_line` before 16 KiB limit, blocking `read_to_end` on UDS | Yes: request line read at http_server.rs:283 has no bound (limit only guards the header loop, cumulatively); `thread::spawn` per connection (409/412/470/481); `read_to_end` at mod.rs:89 + user_sender.rs:21 in synchronous accept loop | **Real vuln content — already ours from three angles** | existing #118, #109; restored **#128**; classification doc pizauth-1 |
| Shell commands via `$SHELL -c` | Yes | By design (config trust); our adjacent variant is the missing timeout on `startup_cmd` specifically | existing #108 |
| Tokens in plain `String`s, no zeroize | Yes (state model) | Memory-hygiene hardening gap; not differentially demonstrable | not added |

## Notes

- External report was built against upstream master; our snapshot is pinned.
  The lockfile rustls version is identical (0.23.43), so the advisory claim
  transfers; other line-number claims were re-checked at our HEAD and hold.
- Its "positive" list (PKCE S256, state check, loopback defaults, 0700 dirs)
  matches what our own reviews found — no conflict.
- Net ledger effect: +5 candidates (#126–#130), one verified (#127).
  pizauth untriaged backlog is now 9 — run `triage pizauth` when the LLM
  endpoint is up.
- Still pending from the pre-fresh-start ledger: snare (5), vibe-kanban (3),
  Who-Targets-Me (5) variant candidates (see `restore-variant-candidates.md`).
