# pizauth #127 — rustls 0.23.43 pin, RUSTSEC-2026-0285 (verified)

Status: candidate #127, **differential gate YES** (2026-09-20). Untriaged,
not reported. Origin: external-agent production audit, surfaced during
reconciliation (see `external-agent-pizauth-reconciliation-20260920.md`);
every factual leg re-verified locally before entering the ledger.

## The finding

`pizauth/Cargo.lock` pins **rustls 0.23.43**, inside the affected range of
**RUSTSEC-2026-0285** (`>=0.23.13, <0.23.45`; patched **0.23.45**, released
2026-09-14). Same bug class as Go's CVE-2025-61730 / GO-2026-4340: rustls
accepted TLS 1.3 handshake messages sent at the wrong encryption level when
they followed a key-changing message in the same record (e.g. a plaintext
`EncryptedExtensions` packed into the `ServerHello` record).

Advisory tempers impact (quote): "The handshake transcript is still
authenticated, so a network-position attacker cannot use this to alter or
complete a handshake; the practical effect is that a peer could send handshake
messages that should be encrypted in plaintext without rustls rejecting the
connection." Exploitability therefore requires a **malicious or compromised
TLS peer**, not merely network position. External agent graded it "Blocker"
for production; for the hunt it is a supply-chain finding (CWE-1104) with a
demonstrated pin and unproven in-target exploit.

## Where rustls is on pizauth's paths

- `Cargo.toml:42` — direct dep, `rustls 0.23.12` resolved to 0.23.43
  (features `ring,std`, default-features off).
- `src/server/http_server.rs:428-483` — the `https_listen` self-signed
  callback TLS server (`ServerConnection`, `Stream`, ring provider). Only
  active when `https_listen` is configured; default deployment is loopback
  HTTP callback only.
- `ureq 3.4.0` (outbound token/auth requests to the provider) uses rustls
  transitively, `platform-verifier` enabled.

## Recorded differential replay

```
vuln:    grep -A1 'name = "rustls"' Cargo.lock   -> rc=0, version = "0.23.43"
control: grep -A1 'name = "ring"' Cargo.lock     -> rc=0, version = "0.17.14"
differential vs control: 1/1 replay pair(s) YES
```

The control shows the same lockfile holds a *patched* dep (ring 0.17.14),
so the vulnerable pin is specific, not a blanket property of the lockfile.

## Before this ships

- `python3 funnel.py report 127` and fill all 14 fields.
- Fix upstream would be `cargo update -p rustls` (>=0.23.45) + a
  `cargo audit` CI gate; our snapshot is read-only, so the finding is the
  committed-lockfile state itself.
- Keep the advisory's tempering in the report wording — do not upgrade this
  to "on-path attacker can break TLS"; that claim would be an FP risk.

## Verification sources

- Local: `pizauth/Cargo.lock` (rustls 0.23.43), `Cargo.toml:42`,
  `http_server.rs` usage sites.
- rustsec.org advisory page RUSTSEC-2026-0285 + Phoronix release note
  (2026-09-14) — one operator lookup on 2026-09-20; not a pipeline lane,
  pipeline stays offline.

Related rows added the same session: #126 (auth_uri guard bypass),
#128 (UDS `read_to_end` DoS), #129 (dump hardcoded key), #130 (socket
peer-cred/umask).
