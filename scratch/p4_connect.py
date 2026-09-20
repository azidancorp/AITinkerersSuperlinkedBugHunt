#!/usr/bin/env python3
"""scratch/p4_connect.py — attack oracle for ledger #128 (P4).

Claim: pizauth's control socket has no peer-credential check and its perms are
left to umask, so another local user can connect and drive the daemon.

The attack requires, for a principal in the OTHERS class (e.g. uid 65534):
  * search (x) permission on EVERY parent directory of the socket, and
  * read/write (rw) permission on the socket itself.

A live cross-uid connect is not possible in this offline sandbox (no root to
setuid), so this oracle reads the kernel's own permission bits (stat) — the
same data path resolution and socket connect are enforced against — and prints
the claimed effect on stdout, diagnostics on stderr.

Usage: p4_connect.py <socket-path>
"""
import os
import stat as statmod
import sys

sock = sys.argv[1]
diag = []

others_search = True
cur = os.path.abspath(sock)
components = []
while True:
    parent, leaf = os.path.split(cur)
    if leaf:
        components.append(cur)
    if parent == cur:
        break
    cur = parent
# components now: [socket, cache_dir, runtime_dir, ..., "/"]

for path in components[:-1]:  # skip "/"
    try:
        st = os.stat(path)
    except OSError as e:
        print("CLAIM_EFFECT=none")
        print(f"diag: stat {path} failed errno={e.errno}", file=sys.stderr)
        sys.exit(0)
    m = statmod.S_IMODE(st.st_mode)
    if os.path.isfile(path) or statmod.S_ISSOCK(st.st_mode):
        is_dir = False
    else:
        is_dir = True
    diag.append(f"{path}: mode={m:o} dir={is_dir}")

sock_st = None
for path in components[:-1]:
    try:
        st = os.lstat(path)
    except OSError:
        continue
    if statmod.S_ISSOCK(st.st_mode):
        sock_st = st
        sock_path = path
        break

if sock_st is None:
    print("CLAIM_EFFECT=none")
    print("diag: no unix socket present at path", file=sys.stderr)
    sys.exit(0)

# others-class search on every dir component above the socket
node = os.path.dirname(sock_path)
while node and node != "/":
    st = os.stat(node)
    if not (statmod.S_IMODE(st.st_mode) & 0o001):
        others_search = False
        diag.append(f"blocked_at={node} (others lack search)")
        break
    node = os.path.dirname(node)

sock_mode = statmod.S_IMODE(sock_st.st_mode)
others_rw = bool(sock_mode & 0o006)
diag.append(f"socket_mode={sock_mode:o} others_rw={others_rw}")

if others_search and others_rw:
    print("CLAIM_EFFECT=unauthorized_access")
else:
    print("CLAIM_EFFECT=none")
print("diag: " + "; ".join(diag), file=sys.stderr)
