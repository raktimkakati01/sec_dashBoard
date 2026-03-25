import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
import enum

DATABASE_URL = "sqlite:///./scanner.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
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
    base_url = Column(String, nullable=False)
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
    url = Column(String, nullable=False)
    method = Column(String, default="GET")
    status_code = Column(Integer, nullable=True)
    content_type = Column(String, nullable=True)
    response_time = Column(Float, nullable=True)
    source = Column(String, nullable=True)  # how it was discovered

    scan = relationship("Scan", back_populates="endpoints")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    endpoint_url = Column(String, nullable=False)
    test_type = Column(String, nullable=False)  # e.g. "sql_injection", "xss"
    severity = Column(SAEnum(Severity), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="findings")


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
