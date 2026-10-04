import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Integer, Float, JSON, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class MonitoringConfig(Base):
    __tablename__ = "monitoring_configs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_id = Column(String(36), ForeignKey("api_targets.id", ondelete="CASCADE"), nullable=False, unique=True)
    
    interval_minutes = Column(Integer, default=15, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    timeout_seconds = Column(Float, default=5.0, nullable=False)
    
    expected_status_codes = Column(JSON, default=lambda: [200, 201, 204, 301, 302], nullable=False)
    latency_threshold_ms = Column(Float, default=1500.0, nullable=False)
    consecutive_failures_alert = Column(Integer, default=2, nullable=False)
    
    check_tls = Column(Boolean, default=True, nullable=False)
    check_security_headers = Column(Boolean, default=True, nullable=False)
    check_openapi_drift = Column(Boolean, default=True, nullable=False)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    api_target = relationship("APITarget", back_populates="monitoring_config")


class MonitoringMetric(Base):
    __tablename__ = "monitoring_metrics"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_id = Column(String(36), ForeignKey("api_targets.id", ondelete="CASCADE"), nullable=False)
    
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
    is_available = Column(Boolean, default=True, nullable=False)
    status_code = Column(Integer, nullable=False)
    response_time_ms = Column(Float, default=0.0, nullable=False)
    
    headers_intact = Column(Boolean, default=True, nullable=False)
    tls_valid = Column(Boolean, default=True, nullable=False)
    error_message = Column(Text, nullable=True)

    api_target = relationship("APITarget", back_populates="monitoring_metrics")


class AnomalyEvent(Base):
    __tablename__ = "anomaly_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_id = Column(String(36), ForeignKey("api_targets.id", ondelete="CASCADE"), nullable=False)
    
    anomaly_type = Column(String(100), nullable=False)  # LATENCY_SPIKE, ERROR_RATE_SURGE, STATUS_DRIFT, DOWNTIME
    severity = Column(String(50), default="HIGH", nullable=False)
    baseline_value = Column(Float, nullable=False)
    observed_value = Column(Float, nullable=False)
    deviation_percent = Column(Float, nullable=False)
    details = Column(Text, nullable=False)
    
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
