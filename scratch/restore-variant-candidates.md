# CLOSED: restore of 17 parked variant candidates — resolved 2026-09-20

Status: CLOSED — fully reconciled; nothing left to execute. Kept for provenance only.

Final resolution per target (details in `claimed-vulnerabilities.md`):
- pizauth (4): RESTORED as #126, #128, #129, #130 (see
  `external-agent-pizauth-reconciliation-20260920.md`); #127 rustls advisory
  added and verified — the first verified row (P8).
- snare: #102/#103 REFUTED at HEAD (S5 request-smuggling, S6 unsigned-queue —
  dead classes); #104/#105 re-registered fresh as #113/#114 (S3/S4).
- vibe-kanban (3): NOT restored — parked-only V9–V11, low priority; revisit only
  if those classes get drilled down.
- Who-Targets-Me: #114–#116 re-registered fresh as #101/#102/#104 (+dups
  #120–#124); #117/#118 REFUTED/anticipated-FP (W5b fix-in-HEAD, W7 unreachable).
- Wave-4 addendum (2026-09-20): parked #117 (W5b) was registered fresh as #136
  and formally gate-rejected (0/3 differential; fix c09e0be is an ancestor of
  HEAD) — see `scratch/wave4-refutations-20260920.md`.

The bulk-restore script (`scratch/add_candidates.sh`) was retired to
`scratch/retired/` — wrong target name inside (`who-targets-me` lowercase).

---

# Original note (historical): restore 17 variant candidates from the pre-fresh-start ledger

Status history: PARTIALLY RESTORED 2026-09-20 (later session), then CLOSED (above).

Source: `.funnel.bak-20260920T130409Z/funnel.db`, table `candidates`,
`WHERE source='variant'` (17 rows, created 11:01-11:19 same day).

- pizauth (4): config.rs:316 high; server/mod.rs:89 med, :444 med; server/state.rs:39 high
- snare (5): httpserver.rs:37 med, :277 high, :329 med, :362 high; jobrunner.rs:216 med
- vibe-kanban (3): executors/cursor.rs:395 high; remote/github_app/service.rs:291 med; utils/msg_store.rs:161 med
- Who-Targets-Me (5): contents/index.js:13 high; collector/platforms/platforms.js:17 low;
  youtube/getAdvertContext.js:7 high; handlers/handleUserCountry.js:5 med; onMessageEventHandler.js:14 high

Restore via the CLI (keeps transitions logged), one `add` per row:

```sh
sqlite3 -json .funnel.bak-20260920T130409Z/funnel.db \
  "SELECT target,title,file,line,severity,cwe,evidence,seed_id FROM candidates WHERE source='variant'"
# then for each row:
python3 funnel.py add <target> --source variant --title '...' --file ... --line N \
  --severity ... --cwe ... --evidence '...' [--seed N]
```

Notes:
- Old DB used target name `who-targets-me` (lowercase); new ledger uses `Who-Targets-Me`.
- seed_id values refer to the OLD seeds table; re-map or drop them (seeds were re-mined, ids differ).
- 8 of the 17 are marked high severity — these were the best signal from the first session.
- Semgrep lane reproduced 1:1 and needs no restore; all its hits are yaml.github-actions.security.* (CI workflow) rules only.
