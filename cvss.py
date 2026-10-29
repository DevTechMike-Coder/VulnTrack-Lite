"""CVSS vector parsing, v3.x base-score calculation, and severity banding.

Scope:
  * CVSS v3.1 / v3.0: full base-score calculation from the vector (FIRST spec).
  * CVSS v4.0: strict structural validation only. v4.0 scoring needs the
    macrovector lookup tables, so the score must be supplied (e.g. by NVD).
"""
from __future__ import annotations

import math
from decimal import Decimal, ROUND_HALF_UP

V3_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": None, "L": None, "H": None},  # depends on scope
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": None, "C": None},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
V3_ORDER = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

V4_BASE = {
    "AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA",
    "VC": "HLN", "VI": "HLN", "VA": "HLN", "SC": "HLN", "SI": "HLN", "SA": "HLN",
}
V4_ORDER = list(V4_BASE)
# Optional threat / environmental / supplemental metrics (value 'X' = not defined).
V4_OPTIONAL = {
    "E": "XAPU",
    "CR": "XHML", "IR": "XHML", "AR": "XHML",
    "MAV": "XNALP", "MAC": "XLH", "MAT": "XNP", "MPR": "XNLH", "MUI": "XNPA",
    "MVC": "XNHL", "MVI": "XNHL", "MVA": "XNHL", "MSC": "XNHL", "MSI": "XNSHL", "MSA": "XNSHL",
    "S": "XNP", "AU": "XNY", "R": "XAUI", "V": "XDC", "RE": "XLMH", "U": "XClearGreenAmberRed",
}


class CvssError(ValueError):
    """Raised for malformed or unsupported CVSS vectors."""


class ParsedVector:
    __slots__ = ("version", "metrics")

    def __init__(self, version: str, metrics: dict[str, str]):
        self.version = version
        self.metrics = metrics


def parse_vector(vector: str) -> ParsedVector:
    if not isinstance(vector, str) or len(vector) > 300:
        raise CvssError("CVSS vector must be a string of at most 300 characters")
    parts = vector.strip().split("/")
    head = parts[0]
    if not head.startswith("CVSS:"):
        raise CvssError("CVSS vector must start with 'CVSS:3.0', 'CVSS:3.1' or 'CVSS:4.0'")
    version = head[5:]
    if version not in ("3.0", "3.1", "4.0"):
        raise CvssError(f"Unsupported CVSS version '{version}' (supported: 3.0, 3.1, 4.0)")

    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if part.count(":") != 1:
            raise CvssError(f"Malformed metric '{part}'")
        key, val = part.split(":")
        if key in metrics:
            raise CvssError(f"Duplicate metric '{key}'")
        metrics[key] = val

    if version == "4.0":
        _validate_v4(metrics)
    else:
        _validate_v3(metrics)
    return ParsedVector(version, metrics)


def _validate_v3(metrics: dict[str, str]) -> None:
    missing = [m for m in V3_ORDER if m not in metrics]
    if missing:
        raise CvssError(f"Missing base metrics: {', '.join(missing)}")
    for key, val in metrics.items():
        if key in V3_METRICS:
            if val not in V3_METRICS[key]:
                raise CvssError(f"Invalid value '{val}' for metric '{key}'")
        elif key not in ("E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"):
            raise CvssError(f"Unknown metric '{key}'")


def _validate_v4(metrics: dict[str, str]) -> None:
    missing = [m for m in V4_ORDER if m not in metrics]
    if missing:
        raise CvssError(f"Missing base metrics: {', '.join(missing)}")
    for key, val in metrics.items():
        allowed = V4_BASE.get(key) or V4_OPTIONAL.get(key)
        if allowed is None:
            raise CvssError(f"Unknown metric '{key}'")
        if key == "U":  # supplemental 'Provider Urgency'
            ok = val in ("X", "Clear", "Green", "Amber", "Red")
        else:
            ok = len(val) == 1 and val in allowed
        if not ok:
            raise CvssError(f"Invalid value '{val}' for metric '{key}'")


def _roundup_31(x: float) -> float:
    """CVSS v3.1 Roundup (Appendix A), avoids floating point artefacts."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def _roundup_30(x: float) -> float:
    return math.ceil(x * 10) / 10.0


def base_score(vector: str) -> float:
    """Return the v3.0/v3.1 base score. Raises CvssError for v4.0 or invalid vectors."""
    pv = parse_vector(vector)
    if pv.version == "4.0":
        raise CvssError("CVSS v4.0 scores cannot be computed locally; supply the score")
    m = pv.metrics
    changed = m["S"] == "C"
    pr = (PR_CHANGED if changed else PR_UNCHANGED)[m["PR"]]
    iss = 1 - (1 - V3_METRICS["C"][m["C"]]) * (1 - V3_METRICS["I"][m["I"]]) * (1 - V3_METRICS["A"][m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * V3_METRICS["AV"][m["AV"]] * V3_METRICS["AC"][m["AC"]] * pr * V3_METRICS["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    roundup = _roundup_31 if pv.version == "3.1" else _roundup_30
    raw = impact + exploitability
    return roundup(min((1.08 if changed else 1.0) * raw, 10))


def severity_for(score: float) -> str:
    """Qualitative severity rating per the CVSS spec (same bands for v3.x and v4.0)."""
    if score < 0 or score > 10:
        raise CvssError("Score must be within 0.0-10.0")
    s = float(Decimal(str(score)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))
    if s == 0.0:
        return "None"
    if s < 4.0:
        return "Low"
    if s < 7.0:
        return "Medium"
    if s < 9.0:
        return "High"
    return "Critical"
