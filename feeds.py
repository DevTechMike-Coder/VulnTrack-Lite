"""Threat-intel feed clients: NVD (CVE + CVSS), CISA KEV, FIRST EPSS.

Hardening:
  * Fixed https endpoints only; the request host must be in ALLOWED_HOSTS.
  * Redirects are refused (a feed host must not bounce us elsewhere).
  * Response size is capped; JSON only; timeouts on every call.
  * Stdlib only (urllib), TLS verification on by default.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterable, Optional

from cvss import CvssError, parse_vector, severity_for

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
ALLOWED_HOSTS = {"services.nvd.nist.gov", "www.cisa.gov", "api.first.org"}

TIMEOUT = 20
MAX_BYTES = 16 * 1024 * 1024
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
KEV_TTL = 6 * 3600


class FeedError(Exception):
    """Upstream feed failure. Message is safe to show to the operator."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _http_get_json(url: str, params: Optional[dict] = None, headers: Optional[dict] = None) -> dict:
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise FeedError("Blocked request to a host that is not an allowed feed")
    req = urllib.request.Request(url, headers={"User-Agent": "VulnTrack-Lite/1.0", "Accept": "application/json", **(headers or {})})
    try:
        with _opener.open(req, timeout=TIMEOUT) as resp:
            raw = resp.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            raise FeedError(f"{parsed.hostname} rate-limited the request (HTTP {e.code}); retry later or set NVD_API_KEY")
        raise FeedError(f"{parsed.hostname} returned HTTP {e.code}")
    except (urllib.error.URLError, TimeoutError, OSError):
        raise FeedError(f"Could not reach {parsed.hostname}")
    if len(raw) > MAX_BYTES:
        raise FeedError(f"Response from {parsed.hostname} exceeded the size limit")
    try:
        data = json.loads(raw)
    except ValueError:
        raise FeedError(f"{parsed.hostname} returned invalid JSON")
    if not isinstance(data, dict):
        raise FeedError(f"{parsed.hostname} returned an unexpected payload")
    return data


# ---------------------------------------------------------------- NVD

def _pick_metric(metrics: dict) -> Optional[dict]:
    """Prefer v3.1, then v4.0, then v3.0; within a version prefer the NVD 'Primary' entry."""
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = [e for e in entries if e.get("type") == "Primary"]
        return (primary or entries)[0].get("cvssData")
    return None


def _title_from(description: str) -> str:
    first = re.split(r"(?<=[.!?])\s", description.strip(), maxsplit=1)[0]
    first = re.sub(r"\s+", " ", first)
    return (first[:97] + "...") if len(first) > 100 else first


def parse_nvd(payload: dict, cve_id: str) -> Optional[dict]:
    vulns = payload.get("vulnerabilities") or []
    cve = next((v.get("cve") for v in vulns if (v.get("cve") or {}).get("id") == cve_id), None)
    if not cve:
        return None
    desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    data = _pick_metric(cve.get("metrics") or {})
    if not data:
        raise FeedError(f"{cve_id} exists in NVD but has no CVSS v3/v4 score yet (awaiting analysis?)")
    vector = data.get("vectorString")
    score = data.get("baseScore")
    if not isinstance(score, (int, float)):
        raise FeedError(f"NVD returned an invalid score for {cve_id}")
    try:
        pv = parse_vector(vector)
        severity_for(float(score))
    except CvssError:
        raise FeedError(f"NVD returned an unparseable CVSS vector for {cve_id}")
    description = (desc or "").strip()
    if len(description) < 10:
        description = (description + " (no description published)").strip()
    return {
        "cve_id": cve_id,
        "title": _title_from(description) if len(_title_from(description)) >= 3 else cve_id,
        "description": description[:1000],
        "score": float(score),
        "cvss_vector": vector,
        "cvss_version": pv.version,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
    }


def fetch_nvd_cve(cve_id: str) -> Optional[dict]:
    if not CVE_RE.match(cve_id):
        raise FeedError("Invalid CVE ID")
    headers = {}
    key = os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    payload = _http_get_json(NVD_URL, {"cveId": cve_id}, headers)
    return parse_nvd(payload, cve_id)


# ---------------------------------------------------------------- CISA KEV

_kev_cache: dict = {"at": 0.0, "data": {}}
_kev_lock = threading.Lock()


def fetch_kev(force: bool = False) -> dict[str, dict]:
    with _kev_lock:
        if not force and _kev_cache["data"] and time.time() - _kev_cache["at"] < KEV_TTL:
            return _kev_cache["data"]
        payload = _http_get_json(KEV_URL)
        entries = payload.get("vulnerabilities")
        if not isinstance(entries, list):
            raise FeedError("CISA KEV catalog had an unexpected format")
        data = {}
        for e in entries:
            cid = e.get("cveID")
            if isinstance(cid, str) and CVE_RE.match(cid):
                data[cid] = {
                    "kev_date_added": e.get("dateAdded"),
                    "kev_due_date": e.get("dueDate"),
                    "kev_ransomware": e.get("knownRansomwareCampaignUse"),
                }
        _kev_cache.update(at=time.time(), data=data)
        return data


# ---------------------------------------------------------------- EPSS

def fetch_epss(cve_ids: Iterable[str]) -> dict[str, dict]:
    ids = [c for c in dict.fromkeys(cve_ids) if CVE_RE.match(c)]
    out: dict[str, dict] = {}
    for i in range(0, len(ids), 50):
        batch = ids[i:i + 50]
        payload = _http_get_json(EPSS_URL, {"cve": ",".join(batch)})
        for row in payload.get("data") or []:
            try:
                out[row["cve"]] = {
                    "epss": float(row["epss"]),
                    "epss_percentile": float(row["percentile"]),
                    "epss_date": row.get("date"),
                }
            except (KeyError, TypeError, ValueError):
                continue
    return out
