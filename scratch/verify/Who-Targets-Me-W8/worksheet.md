# Who-Targets-Me W8 — ledger #132 — stale auth token after account change (VERIFIED)

Status: candidate #132, **differential gate YES 3/3** (2026-09-20).
Origin: WTM production review finding #3 (archived), [doc-only] until this wave.
HEAD: `64e9989c65` (pinned snapshot, unmodified; `git status --porcelain` empty).

## The finding

`src/shared/api/app.js:7-15` reads `general_token` exactly once, in an async
IIFE at module load, and bakes it into the feathers REST client's
`Authorization` header for the lifetime of the background page. Storage can
subsequently change account — `storeUserToken`
(`src/shared/handlers/onMessageEventHandler.js:55-57`) writes a new
`general_token` with **no client rebuild and no `chrome.runtime.reload()`**
(the reload exists only on the registration path, :46). Every upload via
`sendRawLog` after the switch therefore goes out authenticated as the previous
account.

## Differential replay

Harness: `w8-replay.cjs` (this dir) — loads the *actual HEAD source* of
`src/shared/api/app.js` into a `node:vm` sandbox with `@feathersjs/client`,
`readStorage`, and `fetch` stubbed (synthetic canaries only, no network). It
lets the init IIFE capture `canary-token-account-A`, then flips storage to
`canary-token-account-B` via the storeUserToken path and issues an API call,
inspecting the outgoing `Authorization` header. The control is identical minus
the trigger (no account switch).

```
vuln:    node w8-replay.cjs vuln
         current stored general_token: canary-token-account-B
         outgoing Authorization header: canary-token-account-A
         CANARY-COMPROMISED: upload authenticated as previous account -> rc=1
control: node w8-replay.cjs control
         current stored general_token: canary-token-account-A
         outgoing Authorization header: canary-token-account-A
         CLEAN: upload carried the current account token              -> rc=0
gate:    python3 funnel.py verify 132 --repeat 3 --vuln ... --control ...
         differential vs control: 3/3 replay pair(s) YES
```

## Honest severity note

Demonstrated: after a token switch, uploads leave the extension carrying the
**previous** account's bearer token — data-integrity/accounting corruption
(rawlogs misattributed to the prior account) and a credential-lifetime issue
(CWE-613: the old token keeps being used after the user believed they switched
accounts). Not demonstrated: server-side acceptance of the stale pairing, or
cross-account data *read* access (the harness proves header staleness, not
backend authorisation decisions). Registration-triggered account creation is
unaffected because it reloads the extension; the vulnerable switch path is
`storeUserToken` (which, per W1/#101, is also page-reachable — compounding,
but not required for this finding).

## Second-opinion audit addendum (2026-09-20, independent agent)

Audited harness fidelity, trigger honesty and effect assertions from scratch;
verdict **confirmed**, gate re-run from clean 3/3 YES with stdout hashes
identical to the prior lane (`25e8a212ef3d9e68` / `54d031b751b0152d`).

- Transform diffed against HEAD `app.js`: only import/export syntax stripped;
  token-capture IIFE verbatim. Staleness is a property of the real code — the
  feathers stand-in re-uses the configured headers object per request (the
  most charitable dynamic reading) and the header is still stale.
- `storeUserToken` path verified to have no other side effect on the client
  (no `chrome.storage.onChanged` anywhere in `src/`, no reload off the
  registration branch) — the vuln arm's storage flip is the exact real event.
  Deletion (`handleUserDeletion.js:4`) is the same class (removes token, no
  reload).
- Audit fix applied: harness service name `raw-logs` → `submit-rawlogs`
  (matches real `sendRawLog.js` upload path). Output-neutral; hashes unchanged.
- Confirmed entry written:
  `confirmed-vulnerabilities/who-targets-me-stale-token-misattribution.md`
  with evidence in `confirmed-vulnerabilities/wtm-w8-evidence/`.
