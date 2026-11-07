"""CVSS v3.1 base score (FIRST CVSS v3.1 Specification, sections 7.1 to 7.4).

Severity is always computed from the vector; it is never stored or chosen by
hand. The web UI computes scores through `/api/cvss` (this module), so the
formula exists once.
"""

from __future__ import annotations

import math

PREFIX = "CVSS:3.1"

METRICS = [
    ("AV", "Attack Vector", [("N", "Network", "Reachable over the network; almost every web application issue"),
                             ("A", "Adjacent", "Only from the same LAN, Wi-Fi, or VPN"),
                             ("L", "Local", "Needs local access, or a user opening a file"),
                             ("P", "Physical", "Needs physical access to the device")]),
    ("AC", "Attack Complexity", [("L", "Low", "No special conditions; the same request reproduces it"),
                                 ("H", "High", "Needs conditions outside the attacker's control (race, man-in-the-middle position, target-specific preparation)")]),
    ("PR", "Privileges Required", [("N", "None", "Works without logging in"),
                                   ("L", "Low", "Needs an ordinary user account"),
                                   ("H", "High", "Needs an administrator or other privileged account")]),
    ("UI", "User Interaction", [("N", "None", "The attacker alone can do it"),
                                ("R", "Required", "A victim must open a link, view a page, or click (XSS, CSRF)")]),
    ("S", "Scope", [("U", "Unchanged", "The impact stays inside the vulnerable application"),
                    ("C", "Changed", "The impact reaches another security authority (XSS in the user's browser, SSRF to internal systems)")]),
    ("C", "Confidentiality", [("H", "High", "All data, or critical data such as credentials or personal data, can be read"),
                              ("L", "Low", "Some data can be read, without control over what, or it is not critical"),
                              ("N", "None", "Nothing can be read")]),
    ("I", "Integrity", [("H", "High", "Any data can be modified, or a modification has serious consequences"),
                        ("L", "Low", "Some data can be modified, with limited consequences"),
                        ("N", "None", "Nothing can be modified")]),
    ("A", "Availability", [("H", "High", "The service can be stopped completely"),
                           ("L", "Low", "Reduced performance or some functions interrupted"),
                           ("N", "None", "No impact on availability")]),
]
KEYS = [m[0] for m in METRICS]
VALUES = {k: [o[0] for o in opts] for k, _, opts in METRICS}

W_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
W_AC = {"L": 0.77, "H": 0.44}
W_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
W_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
W_UI = {"N": 0.85, "R": 0.62}
W_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
SEVERITIES = [(9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"), (0.0, "None")]


class CvssError(ValueError):
    pass


def roundup(x: float) -> float:
    """Roundup from Appendix A of the specification (avoids floating point errors)."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse(vector: str) -> dict[str, str]:
    v = (vector or "").strip()
    if not v:
        raise CvssError("the vector is empty")
    parts = v.split("/")
    if parts[0].startswith("CVSS:"):
        if parts[0] != PREFIX:
            raise CvssError(f"only CVSS v3.1 is supported ({parts[0]})")
        parts = parts[1:]
    out: dict[str, str] = {}
    for p in parts:
        k, _, val = p.partition(":")
        if k not in VALUES:
            raise CvssError(f"unknown metric {k!r} (base metrics only: {'/'.join(KEYS)})")
        if val not in VALUES[k]:
            raise CvssError(f"bad value for {k}: {val!r} (one of {'/'.join(VALUES[k])})")
        if k in out:
            raise CvssError(f"{k} appears twice")
        out[k] = val
    missing = [k for k in KEYS if k not in out]
    if missing:
        raise CvssError(f"missing metrics: {', '.join(missing)}")
    return out


def normalize(vector: str) -> str:
    m = parse(vector)
    return PREFIX + "/" + "/".join(f"{k}:{m[k]}" for k in KEYS)


def severity(score: float) -> str:
    return next(name for low, name in SEVERITIES if score >= low)


def score(vector: str) -> dict:
    """{'vector', 'score', 'severity', 'impact', 'exploitability'}."""
    m = parse(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - W_CIA[m["C"]]) * (1 - W_CIA[m["I"]]) * (1 - W_CIA[m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    pr = (W_PR_C if changed else W_PR_U)[m["PR"]]
    expl = 8.22 * W_AV[m["AV"]] * W_AC[m["AC"]] * pr * W_UI[m["UI"]]
    if impact <= 0:
        base = 0.0
    elif changed:
        base = roundup(min(1.08 * (impact + expl), 10))
    else:
        base = roundup(min(impact + expl, 10))
    return {"vector": normalize(vector), "score": base, "severity": severity(base),
            "impact": round(max(impact, 0), 1), "exploitability": round(expl, 1)}


def try_score(vector: str | None) -> dict | None:
    try:
        return score(vector) if vector else None
    except CvssError:
        return None
