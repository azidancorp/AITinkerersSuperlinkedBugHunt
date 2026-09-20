# Who-Targets-Me W5a — ledger #131 — EU collection-exclusion bypass (VERIFIED)

Status: candidate #131, **differential gate YES 3/3** (2026-09-20).
Origin: WTM production review finding #4 (archived), [doc-only] until this wave.
HEAD: `64e9989c65` (pinned snapshot, unmodified; `git status --porcelain` empty).

## The finding

The collection gate in `src/shared/handlers/onMessageEventHandler.js:69-71`
suppresses `SEND_RAW_LOG` when `readStorage("userCountry")` is an EU country.
But registration (`src/shared/handlers/handleUserRegistration.js:11-12`) writes
the freshly registered user's country to `userData.country` — never to
`userCountry`. The only writer of `userCountry` is
`onInstalledBackgroundEventListener.js:36-42`, which calls
`handleUserCountry()` (`src/shared/handlers/handleUserCountry.js:7`): that
returns `""` when no `general_token` exists — i.e. always, on a fresh install
with no account yet. Net effect: a user who installs the extension and then
registers from an EU country has **no `userCountry` key at all**, so the gate
passes and collection/uploads proceed until the next install/update event
(typically the next browser restart).

Secondary facet (not separately replayed): a stale cached `userCountry`
survives account deletion and re-registration in another country, because
registration never refreshes the key.

## Differential replay

Harness: `w5a-replay.cjs` (this dir) — loads the *actual HEAD source* of
`onMessageEventHandler.js` into a `node:vm` sandbox (imports stripped,
browser/storage mocked, synthetic canaries only, no network). It drives the
`SEND_RAW_LOG` gate with the exact post-registration storage state of a fresh
German user (`userData.country="de"`, `userCountry` absent). The control is
identical plus the one missing trigger: `userCountry="de"` present — the
key/value the gate was designed to read.

```
vuln:    node w5a-replay.cjs vuln
         storage keys: ["general_token","userData"]   (userCountry ABSENT)
         sendRawLog invocations: 1
         CANARY-COMPROMISED: EU-registered user collected   -> rc=1
control: node w5a-replay.cjs control
         storage keys: ["general_token","userData","userCountry"]
         sendRawLog invocations: 0
         CLEAN: collection gate excluded the EU user        -> rc=0
gate:    python3 funnel.py verify 131 --repeat 3 --vuln ... --control ...
         differential vs control: 3/3 replay pair(s) YES
```

The trigger is exactly the key mismatch: same handler, same user, same
country — the only difference is whether the country sits under the key
registration writes versus the key the gate reads.

## Honest severity note

Demonstrated: an EU user who registers after install is **not excluded** from
rawlog collection for the remainder of the session — a privacy/compliance
breach of the extension's own EU opt-out (uploads require prior consent, so
this is consented collection that the product promises to suppress for EU
users). Not demonstrated: impact beyond the first session (the next
onInstalled event populates `userCountry` via the now-present token), and any
server-side behaviour. Probed in a sandbox with mocked storage, not in a live
browser.
