import uuid
from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Enum as SQLEnum, Text, Float, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class APIEnvironment(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"
    TESTING = "TESTING"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


class RiskClassification(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class MonitoringStatus(str, Enum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    PAUSED = "PAUSED"


class HealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


class AuthType(str, Enum):
    NONE = "NONE"
    API_KEY = "API_KEY"
    BEARER_TOKEN = "BEARER_TOKEN"
    BASIC_AUTH = "BASIC_AUTH"
    OAUTH2 = "OAUTH2"
    CUSTOM_HEADER = "CUSTOM_HEADER"


class APITarget(Base):
    __tablename__ = "api_targets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    base_url = Column(String(512), nullable=False)
    environment = Column(SQLEnum(APIEnvironment), default=APIEnvironment.DEVELOPMENT, nullable=False)
    owner = Column(String(255), nullable=True)
    team = Column(String(255), nullable=True)
    tags = Column(JSON, default=list, nullable=False)
    technology = Column(String(100), default="FastAPI / REST", nullable=True)
    version = Column(String(50), default="v1.0.0", nullable=False)
    
    monitoring_status = Column(SQLEnum(MonitoringStatus), default=MonitoringStatus.ENABLED, nullable=False)
    risk_classification = Column(SQLEnum(RiskClassification), default=RiskClassification.MEDIUM, nullable=False)
    security_score = Column(Float, default=100.0, nullable=False)
    health_status = Column(SQLEnum(HealthStatus), default=HealthStatus.UNKNOWN, nullable=False)
    
    last_scanned_at = Column(DateTime, nullable=True)
    last_monitored_at = Column(DateTime, nullable=True)
    openapi_spec_raw = Column(Text, nullable=True)
    is_authorized = Column(Boolean, default=True, nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    project = relationship("Project", back_populates="apis")
    endpoints = relationship("APIEndpoint", back_populates="api_target", cascade="all, delete-orphan")
    credentials = relationship("APICredential", back_populates="api_target", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="api_target", cascade="all, delete-orphan")
    vulnerabilities = relationship("ScanFinding", back_populates="api_target", cascade="all, delete-orphan")
    monitoring_config = relationship("MonitoringConfig", back_populates="api_target", uselist=False, cascade="all, delete-orphan")
    monitoring_metrics = relationship("MonitoringMetric", back_populates="api_target", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="api_target", cascade="all, delete-orphan")


class APIEndpoint(Base):
    __tablename__ = "api_endpoints"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_id = Column(String(36), ForeignKey("api_targets.id", ondelete="CASCADE"), nullable=False)
    path = Column(String(512), nullable=False)
    method = Column(String(10), default="GET", nullable=False)
    summary = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    parameters = Column(JSON, default=list, nullable=False)
    request_body_schema = Column(JSON, default=dict, nullable=False)
    responses_schema = Column(JSON, default=dict, nullable=False)
    is_authenticated = Column(Boolean, default=False, nullable=False)
    auth_type = Column(SQLEnum(AuthType), default=AuthType.NONE, nullable=False)
    is_deprecated = Column(Boolean, default=False, nullable=False)
    tags = Column(JSON, default=list, nullable=False)
    last_tested_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    api_target = relationship("APITarget", back_populates="endpoints")
    findings = relationship("ScanFinding", back_populates="endpoint", cascade="all, delete-orphan")


class APICredential(Base):
    __tablename__ = "api_credentials"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_id = Column(String(36), ForeignKey("api_targets.id", ondelete="CASCADE"), nullable=False)
    auth_type = Column(SQLEnum(AuthType), nullable=False)
    key_name = Column(String(100), default="default", nullable=False)
    header_name = Column(String(100), default="Authorization", nullable=True)
    encrypted_secret = Column(Text, nullable=False)
    masked_preview = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    api_target = relationship("APITarget", back_populates="credentials")
