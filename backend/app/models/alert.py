import uuid
from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Enum as SQLEnum, Text, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertType(str, Enum):
    CRITICAL_VULNERABILITY = "CRITICAL_VULNERABILITY"
    HIGH_VULNERABILITY = "HIGH_VULNERABILITY"
    API_DOWNTIME = "API_DOWNTIME"
    LATENCY_DEGRADATION = "LATENCY_DEGRADATION"
    ERROR_RATE_SPIKE = "ERROR_RATE_SPIKE"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    NEW_ENDPOINT_DISCOVERED = "NEW_ENDPOINT_DISCOVERED"
    ENDPOINT_REMOVED = "ENDPOINT_REMOVED"
    VULNERABILITY_REAPPEARED = "VULNERABILITY_REAPPEARED"
    TLS_CERT_ISSUE = "TLS_CERT_ISSUE"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"


class AlertStatus(str, Enum):
    TRIGGERED = "TRIGGERED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_id = Column(String(36), ForeignKey("api_targets.id", ondelete="CASCADE"), nullable=False)
    
    title = Column(String(255), nullable=False)
    alert_type = Column(SQLEnum(AlertType), nullable=False)
    severity = Column(SQLEnum(AlertSeverity), default=AlertSeverity.HIGH, nullable=False)
    status = Column(SQLEnum(AlertStatus), default=AlertStatus.TRIGGERED, nullable=False)
    
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)
    recommended_action = Column(Text, nullable=True)
    dedup_key = Column(String(255), index=True, nullable=False)
    
    assigned_user_id = Column(String(36), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)

    api_target = relationship("APITarget", back_populates="alerts")


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    channel_type = Column(String(50), default="WEBHOOK", nullable=False)  # WEBHOOK, EMAIL, IN_APP
    destination_url = Column(String(512), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    filter_min_severity = Column(SQLEnum(AlertSeverity), default=AlertSeverity.MEDIUM, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
