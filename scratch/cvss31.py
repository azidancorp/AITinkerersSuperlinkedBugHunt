#!/usr/bin/env python3
"""CVSS v3.1 base-score calculator (stdlib only).

Implements the equations exactly as published in the FIRST CVSS v3.1
Specification Document, section 7.1 (verified 2026-09-20 against
https://www.first.org/cvss/v3.1/specification-document):

    ISS = 1 - (1-C)(1-I)(1-A)
    Impact (S:U) = 6.42 x ISS
    Impact (S:C) = 7.52 x (ISS - 0.029) - 3.25 x (ISS - 0.02)^15
    Exploitability = 8.22 x AV x AC x PR x UI   (PR:L/PR:H are scope-weighted)
    Base (S:U) = Roundup(min(Impact + Exploitability, 10))
    Base (S:C) = Roundup(min(1.08 x (Impact + Exploitability), 10))

Note the S:C impact term's 15th power (the spec marks it with a footnote
superscript, which is easy to misread as part of the formula or as an
exponent of 1 — an earlier revision of cvss-assessment.md got it wrong).

Usage:
    python3 scratch/cvss31.py 'AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H'
    python3 scratch/cvss31.py --selftest

The selftest asserts six canonical vector shapes with known published
scores; if it passes, the implementation matches FIRST's calculator.
"""

import math
import sys

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},  # S:C overrides L/H below
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR_SCOPE_CHANGED = {"L": 0.68, "H": 0.5}
BASE_KEYS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(x: float) -> float:
    """Smallest 1-decimal number >= x (spec helper, integer-safe)."""
    return math.ceil(round(x * 100000) - 1e-6) / 10 if x * 10 % 1 else math.ceil(x * 10 - 1e-6) / 10


def parse(vector: str) -> dict:
    parts = [p for p in vector.strip().split("/") if p]
    if parts and parts[0].startswith("CVSS:3"):
        parts = parts[1:]
    m = {}
    for p in parts:
        k, _, v = p.partition(":")
        if k not in BASE_KEYS or v not in WEIGHTS.get(k, ("U", "C")):
            raise ValueError(f"bad metric {p!r}")
        m[k] = v
    missing = [k for k in BASE_KEYS if k not in m]
    if missing:
        raise ValueError(f"missing metrics: {', '.join(missing)}")
    return m


def base_score(m: dict) -> float:
    prw = PR_SCOPE_CHANGED.get(m["PR"], WEIGHTS["PR"][m["PR"]]) if m["S"] == "C" else WEIGHTS["PR"][m["PR"]]
    iss = 1 - (1 - WEIGHTS["C"][m["C"]]) * (1 - WEIGHTS["I"][m["I"]]) * (1 - WEIGHTS["A"][m["A"]])
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * WEIGHTS["AV"][m["AV"]] * WEIGHTS["AC"][m["AC"]] * prw * WEIGHTS["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    raw = min(impact + expl, 10) if m["S"] == "U" else min(1.08 * (impact + expl), 10)
    return min(math.ceil(round(raw * 100000) / 100000 * 10 - 1e-6) / 10, 10.0)


def severity(score: float) -> str:
    if score <= 0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"


def selftest() -> int:
    anchors = [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),   # info-leak archetype
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # reflected-XSS archetype
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),   # remote-DoS archetype
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # BlueKeep shape
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 9.6),   # CSRF-to-RCE archetype
        ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # Log4Shell shape
    ]
    ok = True
    for vec, want in anchors:
        got = base_score(parse(vec))
        flag = "OK " if abs(got - want) < 1e-9 else "FAIL"
        ok &= abs(got - want) < 1e-9
        print(f"{flag} {vec} -> {got:.1f} (expected {want})")
    return 0 if ok else 1


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--selftest":
        return selftest()
    for v in argv:
        s = base_score(parse(v))
        print(f"{s:.1f} {severity(s):8s} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
