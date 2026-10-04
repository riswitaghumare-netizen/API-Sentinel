import uuid
from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum as SQLEnum, Text, Integer, Float, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanProfileType(str, Enum):
    QUICK = "QUICK"
    STANDARD = "STANDARD"
    DEEP = "DEEP"
    CUSTOM = "CUSTOM"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_id = Column(String(36), ForeignKey("api_targets.id", ondelete="CASCADE"), nullable=False)
    profile_type = Column(SQLEnum(ScanProfileType), default=ScanProfileType.STANDARD, nullable=False)
    profile_name = Column(String(100), default="Standard Security Scan", nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, default=0.0, nullable=False)
    
    total_requests = Column(Integer, default=0, nullable=False)
    endpoints_tested = Column(Integer, default=0, nullable=False)
    
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    info_count = Column(Integer, default=0, nullable=False)
    
    scanner_modules_executed = Column(JSON, default=list, nullable=False)
    error_message = Column(Text, nullable=True)
    initiated_by_user_id = Column(String(36), nullable=True)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    api_target = relationship("APITarget", back_populates="scans")
    findings = relationship("ScanFinding", back_populates="scan", cascade="all, delete-orphan")
