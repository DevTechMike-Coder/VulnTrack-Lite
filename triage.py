"""Triage priority derived from CVSS, EPSS and CISA KEV.

Rules (evaluated top-down; computed at read time so rule changes apply to old rows):
  P0 Act now   : listed in CISA KEV (known exploited in the wild)
  P1 Urgent    : EPSS >= 0.20, or CVSS >= 9.0 with EPSS >= 0.05
  P2 Plan      : CVSS >= 7.0 or EPSS >= 0.05
  P3 Routine   : everything else
If EPSS has not been fetched yet (epss is None), CVSS alone decides:
  >= 9.0 -> P1, >= 7.0 -> P2, else P3.
"""
from __future__ import annotations

from typing import Optional

LABELS = {0: "Act now", 1: "Urgent", 2: "Plan", 3: "Routine"}


def priority(score: float, epss: Optional[float], kev: bool) -> tuple[int, list[str]]:
    reasons: list[str] = []
    if kev:
        return 0, ["Listed in CISA KEV (exploited in the wild)"]
    if epss is None:
        if score >= 9.0:
            return 1, [f"CVSS {score:.1f} (no EPSS data yet)"]
        if score >= 7.0:
            return 2, [f"CVSS {score:.1f} (no EPSS data yet)"]
        return 3, [f"CVSS {score:.1f} (no EPSS data yet)"]
    if epss >= 0.20:
        return 1, [f"EPSS {epss:.1%} >= 20%"]
    if score >= 9.0 and epss >= 0.05:
        return 1, [f"CVSS {score:.1f} and EPSS {epss:.1%} >= 5%"]
    if score >= 7.0:
        reasons.append(f"CVSS {score:.1f} >= 7.0")
    if epss >= 0.05:
        reasons.append(f"EPSS {epss:.1%} >= 5%")
    if reasons:
        return 2, reasons
    return 3, [f"CVSS {score:.1f}, EPSS {epss:.1%}"]
