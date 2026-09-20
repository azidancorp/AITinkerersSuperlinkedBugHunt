# Writeup: a system that finds software bugs — and then proves them

**AI Tinkerers London × Superlinked — "Hacking Open Source Projects" · 2026-09-20**

## What we built

We built a system that reduces the likelihood of systems getting hacked. It is
not a one-off scan. It is a repeatable pipeline (`funnel.py`, about 870 lines
of Python, no dependencies) that takes an open-source project from raw hints
to proven security bugs:

```
the project's own history → automated scans → review → proof by replay → report
```

The principle: **software suggests, measurement decides.** Every automated
stage — the code scanner, the AI reviewers, the triage model (Superlinked's
Qwen-3.8-27b) — is allowed to be wrong and noisy. They only ever produce
candidates: things worth checking. Nothing is called a bug until it passes the
gate: we run the suspected attack against the real code, side by side with a
harmless version of the same request, three times, from a clean state, using
fake canary data (decoy tokens and files, never real ones). If the attack run
and the harmless run behave the same way, there is no bug, and the claim is
recorded as rejected. Rejections count as useful results, not failures.

## How it ran

We pointed the pipeline at four open-source projects (snare, pizauth,
vibe-kanban, Who-Targets-Me), frozen at one version each:

- **975 leads** dug out of the projects' own history. A project that once
  fixed a certain kind of bug often has more of the same kind still hiding, so
  we started from its past fixes.
- **136 candidates** registered — 100 from the automated scanner, 36 from teams
  of AI agents reviewing code by hand. Reconciled into one deduplicated master
  list of **42 distinct suspected bugs**.
- A **severity ranking** sorted the suspicions by worst-case damage, and proof
  effort went to the worst ones first.
- Independent review teams double-checked every claim and caught duplicate
  reports, a trap involving a dead code file, and several exaggerated impact
  statements before they could reach a final report.

The result: **11 proven vulnerabilities**, each replayed three times through
the gate and written up with full evidence — and **5 formal rejections**, where
the proof step showed that a convincing-looking suspicion was wrong. Wrong
answers score zero in this event, so the pipeline is ruthless about proof.

## What we found

- **vibe-kanban — a web page can take over the app's control panel.** The app
  runs a local service on your computer with no password; its only protection
  is a check that trusts information the caller supplies about itself. A
  malicious website can exploit that to list your files, steal your access
  token, open a terminal, and launch AI agents with instructions of the
  attacker's choosing.
- **vibe-kanban — a booby-trapped error page.** When a login fails, the app
  builds an error page using text straight from the web address, without
  making it safe. One crafted link can run attacker's code inside the app.
- **snare — two ways to knock it over, no password needed.** This tool waits
  for notifications from GitHub and acts on them. Seventeen connections
  sending about 6 bytes per second stop it serving anyone. Separately, a
  single connection sending an endless stream of headers makes its memory
  grow in lockstep with the data sent (192 MB sent → 204 MB of memory) until
  the machine gives up.
- **Who-Targets-Me — four flaws in one browser extension.** Any script on a
  major website the extension touches (Facebook, X, YouTube…) can order it to
  overwrite your account token or delete your account. When you register, it
  copies your secret token into the web page's own storage — a permanent leak.
  Its privacy switch for European users reads a setting that registration
  never saves, so EU users get their data collected anyway. And it remembers
  your login token from startup, so after you switch accounts it keeps sending
  data as the old account.
- **pizauth — a known-flawed building block.** The project locks in a version
  of a security library that has a published flaw. We reported this for what
  it is — a supply-chain hygiene issue, not a demonstrated break-in.

Every report states what was measured, what was inferred, and what was not
demonstrated — with the code version, the test harness, and the captured
outputs attached.

## Why this matters

None of these are exotic hacks. They are **missing boundaries**: a read with
no size limit, a page that forgets to escape text, a setting saved under the
wrong name, a token remembered for too long, a guard that trusts the person
knocking. These are the bugs that ship in real software, and they are what a
systematic pipeline surfaces while human reviewers are still arguing about
whether they are real. Twice during the day, two AI teams disagreed about
whether a claim was genuine; both times the replay proof, not the debate,
settled it.

Throughout: no network access except the local machine, fake canary data only,
target projects untouched, every decision recorded.

## What's next

A human reviews the nine evidence reports, completes the formal submission
fields, replays each bug once more from a clean state, and submits. Three more
suspected bugs (cross-organisation access-control flaws in vibe-kanban) are
confirmed in the source code but cannot be run in our offline setup — they are
labelled as unproven rather than shipped on trust.

---

*Artifacts: `funnel.py` (the pipeline) · `.funnel/funnel.db` (the record of
every decision) · `claimed-vulnerabilities.md` (the 42-claim inventory) ·
`confirmed-vulnerabilities/` (the 9 evidence reports) · `OVERVIEW.md` (visual
summary).*
