import datetime
import enum
import os
from pathlib import Path
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, ForeignKey, Enum as SAEnum, Boolean, inspect, text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./scanner.db")

engine_kwargs = {}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    CRAWLING = "crawling"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    base_url = Column(String(2048), nullable=False)
    status = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    total_endpoints = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    auth_cookies = Column(Text, nullable=True)    # raw cookie string from browser
    auth_headers_json = Column(Text, nullable=True) # JSON dict of extra headers, e.g. {"X-Xsrf-Token": "..."}

    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    url = Column(String(2048), nullable=False)
    method = Column(String(16), default="GET")
    status_code = Column(Integer, nullable=True)
    content_type = Column(String(255), nullable=True)
    response_time = Column(Float, nullable=True)
    source = Column(String(64), nullable=True)  # how it was discovered
    request_content_type = Column(String(255), nullable=True)
    request_params = Column(Text, nullable=True)
    request_example = Column(Text, nullable=True)
    response_body_sample = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="endpoints")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    endpoint_url = Column(String(2048), nullable=False)
    test_type = Column(String(64), nullable=False)  # e.g. "sql_injection", "xss"
    severity = Column(SAEnum(Severity), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="findings")


class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(512), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)

    sessions = relationship("AuthSession", back_populates="user", cascade="all, delete-orphan")
    reset_requests = relationship("PasswordResetRequest", back_populates="user", cascade="all, delete-orphan")


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("admin_users.id"), nullable=False)
    token_hash = Column(String(128), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("AdminUser", back_populates="sessions")


class PasswordResetRequest(Base):
    __tablename__ = "password_reset_requests"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("admin_users.id"), nullable=False)
    code_hash = Column(String(128), nullable=False)
    delivery_target = Column(String(255), nullable=False)
    delivery_status = Column(String(32), default="pending", nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)

    user = relationship("AdminUser", back_populates="reset_requests")


def init_db():
    Base.metadata.create_all(bind=engine)
    _ensure_endpoint_columns()


def _ensure_endpoint_columns():
    inspector = inspect(engine)
    existing = {column["name"] for column in inspector.get_columns("endpoints")}
    alterations = []

    if "request_content_type" not in existing:
        alterations.append("ALTER TABLE endpoints ADD COLUMN request_content_type VARCHAR(255)")
    if "request_params" not in existing:
        alterations.append("ALTER TABLE endpoints ADD COLUMN request_params TEXT")
    if "request_example" not in existing:
        alterations.append("ALTER TABLE endpoints ADD COLUMN request_example TEXT")
    if "response_body_sample" not in existing:
        alterations.append("ALTER TABLE endpoints ADD COLUMN response_body_sample TEXT")

    if not alterations:
        return

    with engine.begin() as connection:
        for statement in alterations:
            connection.execute(text(statement))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
