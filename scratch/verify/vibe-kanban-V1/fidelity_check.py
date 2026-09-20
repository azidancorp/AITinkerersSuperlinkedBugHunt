#!/usr/bin/env python3
"""Fidelity check: every oauth.rs span copied into the V1 harness must occur
VERBATIM in the pinned repo file vibe-kanban/crates/server/src/routes/oauth.rs
@ HEAD d5cbb5380f. Fails loudly on any drift (transcription error or repo
change)."""
import subprocess
import sys

OAUTH = "/home/azidan/AQL/AI/AITinkerers/vibe-kanban/crates/server/src/routes/oauth.rs"
MAIN = "/home/azidan/AQL/AI/AITinkerers/scratch/verify/vibe-kanban-V1/src/main.rs"
EXPECT_HEAD = "d5cbb5380f"

SPANS = [(27, 27, "APP_ICON_BASE64"), (32, 67, "AUTH_PAGE_STYLES"),
         (143, 154, "HandoffCompleteQuery"), (160, 172, "error+missing-code branches"),
         (435, 461, "simple_html_response")]

head = subprocess.run(
    ["git", "-C", "/home/azidan/AQL/AI/AITinkerers/vibe-kanban", "rev-parse", "--short=10", "HEAD"],
    capture_output=True, text=True).stdout.strip()
if head != EXPECT_HEAD:
    sys.exit(f"FAIL: repo HEAD {head} != pinned {EXPECT_HEAD}")

repo_lines = open(OAUTH).read().splitlines()
harness = open(MAIN).read()

for a, b, name in SPANS:
    snippet = "\n".join(repo_lines[a - 1:b])
    if snippet not in harness:
        sys.exit(f"FAIL: span oauth.rs:{a}-{b} ({name}) is NOT verbatim in harness")
    print(f"OK  oauth.rs:{a}-{b} ({name}) verbatim in harness")

# origin.rs is included via #[path] (the real file, not a copy) — say so.
if "vibe-kanban/crates/server/src/middleware/origin.rs" not in harness:
    sys.exit("FAIL: harness does not #[path]-include the real origin.rs")
print("OK  origin.rs included byte-identical via #[path]")
print("FIDELITY OK")
