import os
import sqlite3
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional

# Resolve absolute path for SQLite DB to prevent working directory mismatches
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "vulntrack.db")

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            cve_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            score REAL NOT NULL,
            description TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Modern ASGI lifespan management
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="VulnTrack Lite",
    description="Lightweight Vulnerability Tracker",
    lifespan=lifespan
)

# Pydantic models for validation
class VulnerabilityCreate(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,7}$", description="CVE ID format, e.g., CVE-2026-1234")
    title: str = Field(..., min_length=3, max_length=100)
    severity: str = Field(..., description="Low, Medium, High, Critical")
    score: float = Field(..., ge=0.0, le=10.0, description="CVSS Score from 0.0 to 10.0")
    description: str = Field(..., min_length=10, max_length=1000)

    @field_validator("severity")
    def validate_severity(cls, v):
        allowed = ["Low", "Medium", "High", "Critical"]
        if v not in allowed:
            raise ValueError(f"Severity must be one of {allowed}")
        return v

class VulnerabilityResponse(BaseModel):
    cve_id: str
    title: str
    severity: str
    score: float
    description: str

@app.get("/", response_class=HTMLResponse)
def get_index():
    index_path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h1>Index file not found. Please create index.html in the same directory.</h1>", status_code=404)

@app.get("/api/vulnerabilities", response_model=List[VulnerabilityResponse])
def get_vulnerabilities(severity: Optional[str] = Query(None, description="Filter by severity")):
    conn = get_db_connection()
    cursor = conn.cursor()
    if severity:
        severity = severity.capitalize()
        if severity not in ["Low", "Medium", "High", "Critical"]:
            raise HTTPException(status_code=400, detail="Invalid severity filter. Must be Low, Medium, High, or Critical")
        cursor.execute("SELECT * FROM vulnerabilities WHERE severity = ? ORDER BY score DESC", (severity,))
    else:
        cursor.execute("SELECT * FROM vulnerabilities ORDER BY score DESC")
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]

@app.post("/api/vulnerabilities", response_model=VulnerabilityResponse, status_code=201)
def add_vulnerability(vuln: VulnerabilityCreate):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT 1 FROM vulnerabilities WHERE cve_id = ?", (vuln.cve_id,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail=f"Vulnerability with CVE ID {vuln.cve_id} already exists")
    
    try:
        cursor.execute(
            "INSERT INTO vulnerabilities (cve_id, title, severity, score, description) VALUES (?, ?, ?, ?, ?)",
            (vuln.cve_id, vuln.title, vuln.severity, vuln.score, vuln.description)
        )
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
        
    cursor.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (vuln.cve_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row)

@app.post("/api/clear", status_code=200)
def clear_vulnerabilities():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vulnerabilities")
    conn.commit()
    conn.close()
    return {"message": "Database cleared successfully."}
