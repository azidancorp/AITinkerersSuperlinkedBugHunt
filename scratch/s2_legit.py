#!/usr/bin/env python3
"""scratch/s2_legit.py — legitimate webhook delivery for the S2 (#112) pair.

Sends one well-formed unsigned 'ping' delivery (repos with no secret accept
unsigned requests by design, src/httpserver.rs:295) and reports whether snare
answered within the client timeout. Oracle prints only the claimed effect:
CLAIM_EFFECT=worker_exhaustion_denial when the delivery cannot be served,
CLAIM_EFFECT=none when it is served.
"""
import socket
import sys
import time

HOST = "127.0.0.1"
PORT = int(sys.argv[1])
TIMEOUT = float(sys.argv[2]) if len(sys.argv) > 2 else 6.0

body = b'{"repository":{"owner":{"login":"canary-owner"},"name":"canary-repo"}}'
req = (
    b"POST / HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n"
    b"X-Github-Event: ping\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    b"\r\n" + body
)

start = time.monotonic()
try:
    s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
    s.settimeout(TIMEOUT)
    s.sendall(req)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    elapsed = time.monotonic() - start
    status_line = (data.split(b"\r\n")[0] or b"<no response>").decode(
        errors="replace"
    )
    print(f"LEGIT_RESPONSE={status_line} elapsed={elapsed:.2f}s")
    if data.startswith(b"HTTP/1.1 200"):
        print("CLAIM_EFFECT=none")
    else:
        print("CLAIM_EFFECT=worker_exhaustion_denial")
except OSError as e:
    elapsed = time.monotonic() - start
    print(f"LEGIT_RESPONSE=<{type(e).__name__}: {e}> elapsed={elapsed:.2f}s")
    print("CLAIM_EFFECT=worker_exhaustion_denial")
