from __future__ import annotations

import threading
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from database import init_db, get_db, Scan, Endpoint, Finding, ScanStatus, SessionLocal
from scanner.runner import run_scan

app = FastAPI(title="API Security Scanner", version="1.0.0")

# CORS - allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()


# --- Schemas ---
class ScanCreate(BaseModel):
    base_url: str
    auth_cookies: Optional[str] = None      # raw cookie string from browser
    auth_headers_json: Optional[str] = None # JSON dict or "Name: Value" lines for extra headers


class EndpointOut(BaseModel):
    id: int
    url: str
    method: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    response_time: Optional[float] = None
    source: Optional[str] = None

    class Config:
        from_attributes = True


class FindingOut(BaseModel):
    id: int
    endpoint_url: str
    test_type: str
    severity: str
    title: str
    description: Optional[str] = None
    evidence: Optional[str] = None

    class Config:
        from_attributes = True


class ScanOut(BaseModel):
    id: int
    base_url: str
    status: str
    created_at: str
    completed_at: Optional[str] = None
    total_endpoints: int
    total_findings: int

    class Config:
        from_attributes = True


class ScanDetail(ScanOut):
    endpoints: list[EndpointOut] = []
    findings: list[FindingOut] = []


# --- Background scan runner ---
def _run_scan_in_thread(scan_id: int, base_url: str,
                        cookies: str = None, headers_json: str = None):
    """Run scan in a background thread with its own DB session."""
    db = SessionLocal()
    try:
        run_scan(scan_id, base_url, db, cookies=cookies, headers_json=headers_json)
    finally:
        db.close()


# --- Routes ---
@app.post("/api/scan", response_model=ScanOut)
def start_scan(body: ScanCreate, db: Session = Depends(get_db)):
    """Start a new scan for the given base URL."""
    url = body.base_url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="base_url must start with http:// or https://")

    scan = Scan(
        base_url=url,
        status=ScanStatus.PENDING,
        auth_cookies=body.auth_cookies,
        auth_headers_json=body.auth_headers_json,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Launch scan in background thread
    thread = threading.Thread(
        target=_run_scan_in_thread,
        args=(scan.id, url),
        kwargs={"cookies": body.auth_cookies, "headers_json": body.auth_headers_json},
        daemon=True,
    )
    thread.start()

    return _scan_to_dict(scan)


@app.get("/api/scans", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db)):
    """List all scans, newest first."""
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return [_scan_to_dict(s) for s in scans]


@app.get("/api/scan/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get full scan details including endpoints and findings."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        **_scan_to_dict(scan),
        "endpoints": [_endpoint_to_dict(e) for e in scan.endpoints],
        "findings": [_finding_to_dict(f) for f in scan.findings],
    }


@app.get("/api/scan/{scan_id}/endpoints", response_model=list[EndpointOut])
def get_scan_endpoints(scan_id: int, db: Session = Depends(get_db)):
    """Get discovered endpoints for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return [_endpoint_to_dict(e) for e in scan.endpoints]


@app.get("/api/scan/{scan_id}/findings", response_model=list[FindingOut])
def get_scan_findings(scan_id: int, db: Session = Depends(get_db)):
    """Get vulnerability findings for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return [_finding_to_dict(f) for f in scan.findings]


# --- Helpers ---
def _scan_to_dict(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "base_url": scan.base_url,
        "status": scan.status.value if scan.status else "pending",
        "created_at": scan.created_at.isoformat() if scan.created_at else "",
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "total_endpoints": scan.total_endpoints or 0,
        "total_findings": scan.total_findings or 0,
    }


def _endpoint_to_dict(ep: Endpoint) -> dict:
    return {
        "id": ep.id,
        "url": ep.url,
        "method": ep.method,
        "status_code": ep.status_code,
        "content_type": ep.content_type,
        "response_time": ep.response_time,
        "source": ep.source,
    }


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "endpoint_url": f.endpoint_url,
        "test_type": f.test_type,
        "severity": f.severity.value if f.severity else "info",
        "title": f.title,
        "description": f.description,
        "evidence": f.evidence,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
