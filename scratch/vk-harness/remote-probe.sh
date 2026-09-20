#!/bin/bash
# Replay guard for vibe-kanban remote-crate claims (ledger #133/#134/#135).
# The differential gate runs the stored vuln/control commands on every verify.
# When the harness server is absent, BOTH sides must print byte-identical
# output so the gate honestly records "no demonstrated effect" rather than a
# spurious differential from differing error text.
# When a server IS up on 127.0.0.1:8081, the wrapped command executes for real.
if ! curl -sf -m 2 -o /dev/null http://127.0.0.1:8081/v1/health; then
  echo "HARNESS-BLOCKED (not a refutation): vibe-kanban remote server not running on 127.0.0.1:8081."
  echo "Blockers at 2026-09-20: remote crate not buildable offline (aws-sdk-s3/azure_*/opentelemetry-*/axum-extra/ipnetwork/urlencoding/reqwest-0.12 absent from cargo cache; private billing git dep unfetchable) and no PostgreSQL on host (docker socket denied)."
  exit 0
fi
exec "$@"
