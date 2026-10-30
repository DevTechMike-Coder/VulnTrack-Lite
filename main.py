import hmac
import logging
import os
import sqlite3
import sys
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, model_validator

import feeds
from cvss import CvssError, base_score, parse_vector, severity_for
from triage import LABELS, priority as compute_priority

log = logging.getLogger("vulntrack")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.environ.get("VULNTRACK_DB") or os.path.join(BASE_DIR, "vulntrack.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
SEVERITIES = ["None", "Low", "Medium", "High", "Critical"]
CVE_PATTERN = r"^CVE-\d{4}-\d{4,7}$"
MAX_BODY = 64 * 1024
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "VulnTrack"
CLEAR_CONFIRM = "delete-all"

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


def _token() -> Optional[str]:
    return os.environ.get("VULNTRACK_TOKEN") or None


def _allowed_hosts() -> set:
    extra = {h.strip().lower() for h in os.environ.get("VULNTRACK_ALLOWED_HOSTS", "").split(",") if h.strip()}
    return LOCAL_HOSTS | extra


# ------------------------------------------------------------------ database

NEW_COLUMNS = {  # static DDL only; never built from user input
    "cvss_vector": "TEXT",
    "cvss_version": "TEXT",
    "published": "TEXT",
    "last_modified": "TEXT",
    "epss": "REAL",
    "epss_percentile": "REAL",
    "epss_date": "TEXT",
    "kev": "INTEGER NOT NULL DEFAULT 0",
    "kev_date_added": "TEXT",
    "kev_due_date": "TEXT",
    "kev_ransomware": "TEXT",
    "source": "TEXT NOT NULL DEFAULT 'manual'",
    "enriched_at": "TEXT",
}


def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db():
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db():
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                score REAL NOT NULL,
                description TEXT NOT NULL
            )
            """
        )
        existing = {r["name"] for r in conn.execute("PRAGMA table_info(vulnerabilities)")}
        for name, ddl in NEW_COLUMNS.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {name} {ddl}")
        # Severity is derived from score; repair rows written by older versions.
        for row in conn.execute("SELECT cve_id, score, severity FROM vulnerabilities").fetchall():
            derived = severity_for(row["score"])
            if derived != row["severity"]:
                conn.execute("UPDATE vulnerabilities SET severity = ? WHERE cve_id = ?", (derived, row["cve_id"]))
        conn.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="VulnTrack Lite",
    description="Lightweight vulnerability tracker with CVSS, EPSS and CISA KEV triage",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# ------------------------------------------------------------------ models


class VulnerabilityCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(..., pattern=CVE_PATTERN, description="CVE ID, e.g. CVE-2026-1234")
    title: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., min_length=10, max_length=1000)
    cvss_vector: Optional[str] = Field(None, max_length=300)
    score: Optional[float] = Field(None, ge=0.0, le=10.0, description="Required unless a CVSS v3.x vector is given")
    severity: Optional[str] = Field(None, description="Deprecated. Derived from score; if sent it must match")

    @model_validator(mode="after")
    def derive(self):
        score = self.score
        if self.cvss_vector:
            try:
                pv = parse_vector(self.cvss_vector)
                if pv.version == "4.0":
                    if score is None:
                        raise ValueError("score is required for CVSS v4.0 vectors (v4.0 is validated, not computed)")
                else:
                    computed = base_score(self.cvss_vector)
                    if score is not None and abs(score - computed) > 0.05:
                        raise ValueError(f"score {score} does not match vector (computed {computed})")
                    score = computed
            except CvssError as e:
                raise ValueError(str(e))
        elif score is None:
            raise ValueError("Provide either a CVSS vector or a score")
        derived = severity_for(score)
        if self.severity is not None and self.severity != derived:
            raise ValueError(f"severity '{self.severity}' does not match score {score} ({derived})")
        self.score = score
        self.severity = derived
        return self


class ImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str = Field(..., pattern=CVE_PATTERN)


class VulnerabilityResponse(BaseModel):
    cve_id: str
    title: str
    severity: str
    score: float
    description: str
    cvss_vector: Optional[str] = None
    cvss_version: Optional[str] = None
    published: Optional[str] = None
    last_modified: Optional[str] = None
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_date: Optional[str] = None
    kev: bool = False
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    kev_ransomware: Optional[str] = None
    source: str = "manual"
    enriched_at: Optional[str] = None
    priority: int
    priority_label: str
    priority_reasons: List[str]


def to_response(row: sqlite3.Row) -> dict:
    data = dict(row)
    data["kev"] = bool(data["kev"])
    p, reasons = compute_priority(data["score"], data["epss"], data["kev"])
    data.update(priority=p, priority_label=LABELS[p], priority_reasons=reasons)
    return data


# ------------------------------------------------------------------ security middleware


class RateLimiter:
    def __init__(self):
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str, limit: int, window: int = 60) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


limiter = RateLimiter()


def _deny(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


@app.middleware("http")
async def security_gate(request: Request, call_next):
    host = (request.headers.get("host") or "").lower()
    hostname = host[1:host.index("]")] if host.startswith("[") and "]" in host else host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    if hostname not in _allowed_hosts():  # blocks DNS-rebinding against the local server
        return _deny(400, "Invalid host header")

    path = request.url.path
    is_api = path.startswith("/api/")
    unsafe = request.method not in ("GET", "HEAD", "OPTIONS")

    if is_api:
        if unsafe:
            if request.headers.get(CSRF_HEADER) != CSRF_VALUE:
                return _deny(403, "Missing required request header")
            origin = request.headers.get("origin")
            if origin and urlparse(origin).netloc.lower() != host:
                return _deny(403, "Cross-origin request refused")
        try:
            if int(request.headers.get("content-length", "0")) > MAX_BODY:
                return _deny(413, "Request body too large")
        except ValueError:
            return _deny(400, "Invalid Content-Length")

        token = _token()
        if token:
            supplied = request.headers.get("authorization", "")
            if not (supplied.startswith("Bearer ") and hmac.compare_digest(supplied[7:].encode(), token.encode())):
                return _deny(401, "Authentication required")

        client = request.client.host if request.client else "unknown"
        if path in ("/api/vulnerabilities/import", "/api/enrich"):
            if not limiter.allow(f"feed:{client}", 10):
                return _deny(429, "Too many requests")
        elif unsafe and not limiter.allow(f"write:{client}", 120):
            return _deny(429, "Too many requests")

    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if is_api:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


# ------------------------------------------------------------------ routes


@app.get("/", include_in_schema=False)
def get_index():
    index_path = os.path.join(BASE_DIR, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(index_path, media_type="text/html")


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _fetch_one(conn, cve_id: str):
    return conn.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (cve_id,)).fetchone()


def _insert(conn, rec: dict, source: str):
    try:
        conn.execute(
            """INSERT INTO vulnerabilities
               (cve_id, title, severity, score, description, cvss_vector, cvss_version, published, last_modified, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rec["cve_id"], rec["title"], severity_for(rec["score"]), rec["score"], rec["description"],
                rec.get("cvss_vector"), rec.get("cvss_version"), rec.get("published"), rec.get("last_modified"), source,
            ),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail=f"Vulnerability with CVE ID {rec['cve_id']} already exists")


def _apply_enrichment(conn, ids: List[str]) -> List[str]:
    """Refresh KEV + EPSS for the given CVEs. Returns human-readable warnings for partial failures."""
    warnings: List[str] = []
    now = _utcnow()
    try:
        kev = feeds.fetch_kev(force=True)
    except feeds.FeedError as e:
        kev = None
        warnings.append(f"KEV: {e}")
    try:
        epss = feeds.fetch_epss(ids)
    except feeds.FeedError as e:
        epss = {}
        warnings.append(f"EPSS: {e}")

    for cid in ids:
        if kev is not None:
            entry = kev.get(cid) or {}
            conn.execute(
                "UPDATE vulnerabilities SET kev = ?, kev_date_added = ?, kev_due_date = ?, kev_ransomware = ?, enriched_at = ? WHERE cve_id = ?",
                (
                    1 if entry else 0,
                    entry.get("kev_date_added"), entry.get("kev_due_date"), entry.get("kev_ransomware"),
                    now, cid,
                ),
            )
        if cid in epss:
            e = epss[cid]
            conn.execute(
                "UPDATE vulnerabilities SET epss = ?, epss_percentile = ?, epss_date = ?, enriched_at = ? WHERE cve_id = ?",
                (e["epss"], e["epss_percentile"], e["epss_date"], now, cid),
            )
    conn.commit()
    return warnings


@app.get("/api/vulnerabilities", response_model=List[VulnerabilityResponse])
def get_vulnerabilities(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    priority: Optional[int] = Query(None, ge=0, le=3, description="Filter by triage priority (0-3)"),
    kev: Optional[bool] = Query(None, description="Only CISA KEV entries when true"),
):
    if severity is not None:
        severity = severity.capitalize()
        if severity not in SEVERITIES:
            raise HTTPException(status_code=400, detail=f"Invalid severity filter. Must be one of {SEVERITIES}")
    with db() as conn:
        if severity:
            rows = conn.execute("SELECT * FROM vulnerabilities WHERE severity = ?", (severity,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM vulnerabilities").fetchall()
    items = [to_response(r) for r in rows]
    if priority is not None:
        items = [i for i in items if i["priority"] == priority]
    if kev is not None:
        items = [i for i in items if i["kev"] == kev]
    items.sort(key=lambda i: (i["priority"], -(i["epss"] or 0.0), -i["score"], i["cve_id"]))
    return items


@app.get("/api/vulnerabilities/{cve_id}", response_model=VulnerabilityResponse)
def get_vulnerability(cve_id: str = Path(..., pattern=CVE_PATTERN)):
    with db() as conn:
        row = _fetch_one(conn, cve_id)
    if not row:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return to_response(row)


@app.post("/api/vulnerabilities", response_model=VulnerabilityResponse, status_code=201)
def add_vulnerability(vuln: VulnerabilityCreate):
    with db() as conn:
        _insert(conn, vuln.model_dump(), "manual")
        return to_response(_fetch_one(conn, vuln.cve_id))


@app.post("/api/vulnerabilities/import", response_model=VulnerabilityResponse, status_code=201)
def import_from_nvd(req: ImportRequest):
    with db() as conn:
        if _fetch_one(conn, req.cve_id):
            raise HTTPException(status_code=409, detail=f"Vulnerability with CVE ID {req.cve_id} already exists")
        try:
            rec = feeds.fetch_nvd_cve(req.cve_id)
        except feeds.FeedError as e:
            raise HTTPException(status_code=502, detail=str(e))
        if rec is None:
            raise HTTPException(status_code=404, detail=f"{req.cve_id} was not found in NVD")
        _insert(conn, rec, "nvd")
        _apply_enrichment(conn, [req.cve_id])  # best effort; failures leave the fields empty
        return to_response(_fetch_one(conn, req.cve_id))


@app.post("/api/enrich")
def enrich_all():
    with db() as conn:
        ids = [r["cve_id"] for r in conn.execute("SELECT cve_id FROM vulnerabilities")]
        if not ids:
            return {"updated": 0, "kev_hits": 0, "warnings": []}
        warnings = _apply_enrichment(conn, ids)
        kev_hits = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE kev = 1").fetchone()[0]
    return {"updated": len(ids), "kev_hits": kev_hits, "warnings": warnings}


@app.delete("/api/vulnerabilities/{cve_id}", status_code=200)
def delete_vulnerability(cve_id: str = Path(..., pattern=CVE_PATTERN)):
    with db() as conn:
        cur = conn.execute("DELETE FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
        conn.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return {"message": f"{cve_id} deleted."}


@app.delete("/api/vulnerabilities", status_code=200)
def clear_vulnerabilities(request: Request):
    if request.headers.get("x-confirm-clear") != CLEAR_CONFIRM:
        raise HTTPException(status_code=400, detail="Missing confirmation header")
    with db() as conn:
        conn.execute("DELETE FROM vulnerabilities")
        conn.commit()
    return {"message": "Database cleared successfully."}


# ------------------------------------------------------------------ launcher


def run():
    import uvicorn

    host = os.environ.get("VULNTRACK_HOST", "127.0.0.1")
    port = int(os.environ.get("VULNTRACK_PORT", "8000"))
    if host not in LOCAL_HOSTS:
        token = _token()
        if not token or len(token) < 16:
            sys.exit("Refusing to bind to a non-local address without VULNTRACK_TOKEN (>= 16 chars).")
        if len(_allowed_hosts() - LOCAL_HOSTS) == 0:
            sys.exit("Set VULNTRACK_ALLOWED_HOSTS to the hostname(s) clients will use.")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run()
