from __future__ import annotations

import datetime
import os
import threading
from typing import Optional
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from pydantic import BaseModel
from sqlalchemy.orm import Session

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from database import (
    init_db,
    get_db,
    Scan,
    Endpoint,
    Finding,
    ScanStatus,
    SessionLocal,
    AdminUser,
    AuthSession,
    PasswordResetRequest,
)
from security import (
    hash_password,
    verify_password,
    generate_session_token,
    hash_token,
    generate_reset_code,
    send_email,
)
from scanner.runner import run_scan

app = FastAPI(title="API Security Scanner", version="1.0.0")

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "security@vantagecircle.com").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Working925165@#$")
SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "12"))
RESET_CODE_TTL_MINUTES = int(os.getenv("RESET_CODE_TTL_MINUTES", "15"))

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
    db = SessionLocal()
    try:
        user = db.query(AdminUser).filter(AdminUser.email == ADMIN_EMAIL).first()
        if not user:
            user = AdminUser(email=ADMIN_EMAIL, password_hash=hash_password(ADMIN_PASSWORD))
            db.add(user)
        else:
            user.password_hash = hash_password(ADMIN_PASSWORD)
            user.is_active = True
        db.commit()
    finally:
        db.close()


# --- Schemas ---
class ScanCreate(BaseModel):
    base_url: str
    auth_cookies: Optional[str] = None      # raw cookie string from browser
    auth_headers_json: Optional[str] = None # JSON dict or "Name: Value" lines for extra headers
    enable_nuclei: bool = False
    nuclei_tags: Optional[str] = None


class LoginRequest(BaseModel):
    email: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    email: str
    code: str
    new_password: str


class AdminUserOut(BaseModel):
    id: int
    email: str

    class Config:
        from_attributes = True


class AuthResponse(BaseModel):
    token: str
    user: AdminUserOut


class MessageResponse(BaseModel):
    message: str


class EndpointOut(BaseModel):
    id: int
    url: str
    method: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    response_time: Optional[float] = None
    source: Optional[str] = None
    request_content_type: Optional[str] = None
    request_params: Optional[str] = None
    request_example: Optional[str] = None
    response_body_sample: Optional[str] = None

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


def _require_admin(
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(default=None),
) -> AdminUser:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")

    token_value = authorization.removeprefix("Bearer ").strip()
    if not token_value:
        raise HTTPException(status_code=401, detail="Authentication required")

    token_hash_value = hash_token(token_value)
    session = (
        db.query(AuthSession)
        .filter(
            AuthSession.token_hash == token_hash_value,
            AuthSession.expires_at > datetime.datetime.utcnow(),
        )
        .first()
    )
    if not session or not session.user or not session.user.is_active:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return session.user


# --- Background scan runner ---
def _run_scan_in_thread(scan_id: int, base_url: str,
                        cookies: str = None, headers_json: str = None,
                        enable_nuclei: bool = False, nuclei_tags: str = None):
    """Run scan in a background thread with its own DB session."""
    db = SessionLocal()
    try:
        run_scan(
            scan_id,
            base_url,
            db,
            cookies=cookies,
            headers_json=headers_json,
            enable_nuclei=enable_nuclei,
            nuclei_tags=nuclei_tags,
        )
    finally:
        db.close()


# --- Routes ---
@app.post("/api/auth/login", response_model=AuthResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = (
        db.query(AdminUser)
        .filter(AdminUser.email == body.email.strip().lower(), AdminUser.is_active.is_(True))
        .first()
    )
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token, token_hash_value = generate_session_token()
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=SESSION_TTL_HOURS)
    session = AuthSession(user_id=user.id, token_hash=token_hash_value, expires_at=expires_at)
    db.add(session)
    db.commit()

    return {"token": token, "user": {"id": user.id, "email": user.email}}


@app.get("/api/auth/me", response_model=AdminUserOut)
def get_current_admin(current_user: AdminUser = Depends(_require_admin)):
    return current_user


@app.post("/api/auth/logout", response_model=MessageResponse)
def logout(
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(default=None),
    current_user: AdminUser = Depends(_require_admin),
):
    token_value = authorization.removeprefix("Bearer ").strip()
    db.query(AuthSession).filter(AuthSession.token_hash == hash_token(token_value)).delete()
    db.commit()
    return {"message": f"Signed out {current_user.email}"}


@app.post("/api/auth/forgot-password", response_model=MessageResponse)
def forgot_password(body: ForgotPasswordRequest, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    user = db.query(AdminUser).filter(AdminUser.email == email, AdminUser.is_active.is_(True)).first()
    if not user:
        return {"message": "If the account exists, a verification code has been sent."}

    code = generate_reset_code()
    reset_request = PasswordResetRequest(
        user_id=user.id,
        code_hash=hash_token(code),
        delivery_target=email,
        delivery_status="pending",
        expires_at=datetime.datetime.utcnow() + datetime.timedelta(minutes=RESET_CODE_TTL_MINUTES),
    )
    db.add(reset_request)
    db.commit()

    try:
        send_email(
            email,
            "Security Dashboard password reset code",
            (
                f"A password reset was requested for the security dashboard.\n\n"
                f"Verification code: {code}\n"
                f"This code expires in {RESET_CODE_TTL_MINUTES} minutes.\n\n"
                f"If you did not request this change, ignore this email."
            ),
        )
        reset_request.delivery_status = "sent"
        db.commit()
    except Exception as exc:
        reset_request.delivery_status = "failed"
        db.commit()
        raise HTTPException(status_code=500, detail=f"Reset email could not be delivered: {exc}")

    return {"message": f"Verification code sent to {email}"}


@app.post("/api/auth/reset-password", response_model=MessageResponse)
def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    user = db.query(AdminUser).filter(AdminUser.email == email, AdminUser.is_active.is_(True)).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset request")

    reset_request = (
        db.query(PasswordResetRequest)
        .filter(
            PasswordResetRequest.user_id == user.id,
            PasswordResetRequest.used_at.is_(None),
            PasswordResetRequest.expires_at > datetime.datetime.utcnow(),
        )
        .order_by(PasswordResetRequest.created_at.desc())
        .first()
    )
    if not reset_request or reset_request.code_hash != hash_token(body.code.strip()):
        raise HTTPException(status_code=400, detail="Invalid or expired verification code")
    if len(body.new_password) < 12:
        raise HTTPException(status_code=400, detail="New password must be at least 12 characters")

    user.password_hash = hash_password(body.new_password)
    reset_request.used_at = datetime.datetime.utcnow()
    db.query(AuthSession).filter(AuthSession.user_id == user.id).delete()
    db.commit()

    return {"message": "Password updated successfully. Please sign in again."}


@app.post("/api/scan", response_model=ScanOut)
def start_scan(
    body: ScanCreate,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(_require_admin),
):
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
        kwargs={
            "cookies": body.auth_cookies,
            "headers_json": body.auth_headers_json,
            "enable_nuclei": body.enable_nuclei,
            "nuclei_tags": body.nuclei_tags,
        },
        daemon=True,
    )
    thread.start()

    return _scan_to_dict(scan)


@app.get("/api/scans", response_model=list[ScanOut])
def list_scans(
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(_require_admin),
):
    """List all scans, newest first."""
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return [_scan_to_dict(s) for s in scans]


@app.get("/api/scan/{scan_id}", response_model=ScanDetail)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(_require_admin),
):
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
def get_scan_endpoints(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(_require_admin),
):
    """Get discovered endpoints for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return [_endpoint_to_dict(e) for e in scan.endpoints]


@app.get("/api/scan/{scan_id}/findings", response_model=list[FindingOut])
def get_scan_findings(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: AdminUser = Depends(_require_admin),
):
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
        "request_content_type": ep.request_content_type,
        "request_params": ep.request_params,
        "request_example": ep.request_example,
        "response_body_sample": ep.response_body_sample,
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
