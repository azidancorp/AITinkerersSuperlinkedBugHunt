# pizauth — Cargo.lock pins rustls 0.23.43 inside RUSTSEC-2026-0285 range

**Status: CONFIRMED as a dependency-advisory/pin finding (CWE-1104). Not a
demonstrated exploit.** Ledger candidate **#127** (manual), severity med,
stage `verified` — where "verified" means a **pin-presence differential**,
not an exploit replay. Independently re-audited 2026-09-20 by second
opinion; every leg below re-checked offline against the snapshot.

## Pin evidence (re-verified locally)

- `pizauth/Cargo.lock:1395-1396` — `name = "rustls"`, `version = "0.23.43"`.
- `pizauth/Cargo.toml:42` — direct dependency:
  `rustls = { version = "0.23.12", features = ["ring", "std"], default-features = false }`.
  The `^0.23.12` window permits 0.23.43, so the lockfile resolution is what
  pins the vulnerable version.
- `0.23.43` is inside RUSTSEC-2026-0285's affected range **`>=0.23.13, <0.23.45`**
  (patched **0.23.45**, released 2026-09-14).

## Dependency path (not a stale lockfile entry)

`cargo tree -i rustls --offline --locked` from `pizauth/`:

```
rustls v0.23.43
├── pizauth v1.1.0 (.../pizauth)          <- direct first-party dep
├── rustls-platform-verifier v0.7.0
│   └── ureq v3.4.0
│       └── pizauth v1.1.0                <- outbound token/auth requests
└── ureq v3.4.0 (*)
```

First-party code usage: `src/server/http_server.rs:20` (imports), `:428`
(installs `rustls::crypto::ring::default_provider()`), `:473`
(`ServerConnection::new`), `:483` (`rustls::Stream`) — the `https_listen`
self-signed callback TLS server. That server only runs when `https_listen`
is configured (`config.rs:52`, `None => Ok(None)`); the default deployment
is loopback HTTP. rustls is also the TLS backend for `ureq 3.4.0`
(`Cargo.toml:38`, `platform-verifier` feature) on outbound OAuth2
token/auth requests.

## Advisory facts and provenance

Per the workspace finding record (`scratch/pizauth-rustls-advisory-20260920.md`,
cross-checked against `scratch/external-agent-pizauth-reconciliation-20260920.md`
and `scratch/finding-type-classification-20260920.md`; facts originated from a
single documented operator lookup of rustsec.org on 2026-09-20 — the audit
environment is offline and did **not** re-fetch them):

- RUSTSEC-2026-0285: rustls accepted TLS 1.3 handshake messages sent at the
  wrong encryption level when they followed a key-changing message in the same
  record (e.g. a plaintext `EncryptedExtensions` packed into the
  `ServerHello` record). Same bug class as Go's CVE-2025-61730 /
  GO-2026-4340.
- Affected `>=0.23.13, <0.23.45`; patched `>=0.23.45`.

**Impact, in the advisory's own (tempering) words:** "The handshake
transcript is still authenticated, so a network-position attacker cannot use
this to alter or complete a handshake; the practical effect is that a peer
could send handshake messages that should be encrypted in plaintext without
rustls rejecting the connection." Exploitability therefore requires a
**malicious or compromised TLS peer** — for pizauth: the connecting client of
the optional `https_listen` callback server, or the OAuth2 provider (or
something controlling it) for ureq outbound. **Do not escalate this to
"on-path attacker breaks TLS" — the advisory explicitly rules that out.**

## What was and was NOT demonstrated

- Demonstrated: the vulnerable pin exists in the committed lockfile, rustls
  is on pizauth's active dependency tree (direct + ureq), and the version
  sits inside the advisory's affected range. The recorded differential
  (`grep -A1 'name = "rustls"'` vs `'name = "ring"'` on Cargo.lock →
  `0.23.43` vs `0.17.14`) confirms the pin is specific, not a blanket
  lockfile property.
- NOT demonstrated: any in-target exploitation — no wrong-encryption-level
  handshake was replayed against pizauth's `https_listen` server or ureq
  outbound path; no plaintext-handshake acceptance observed; no impact on
  token confidentiality or callback integrity shown.
- Remediation upstream: `cargo update -p rustls` (>=0.23.45) plus a
  `cargo audit` CI gate; this snapshot is read-only, so the finding is the
  committed-lockfile state itself.
