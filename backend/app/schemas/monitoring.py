from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel


class MonitoringConfigUpdate(BaseModel):
    interval_minutes: Optional[int] = None
    is_active: Optional[bool] = None
    timeout_seconds: Optional[float] = None
    expected_status_codes: Optional[List[int]] = None
    latency_threshold_ms: Optional[float] = None
    consecutive_failures_alert: Optional[int] = None
    check_tls: Optional[bool] = None
    check_security_headers: Optional[bool] = None
    check_openapi_drift: Optional[bool] = None


class MonitoringConfigResponse(BaseModel):
    id: str
    api_id: str
    interval_minutes: int
    is_active: bool
    timeout_seconds: float
    expected_status_codes: List[int]
    latency_threshold_ms: float
    consecutive_failures_alert: int
    check_tls: bool
    check_security_headers: bool
    check_openapi_drift: bool
    created_at: datetime
    updated_at: datetime


class MetricPoint(BaseModel):
    timestamp: datetime
    is_available: bool
    status_code: int
    response_time_ms: float
    headers_intact: bool
    tls_valid: bool
    error_message: Optional[str] = None


class AnomalyResponse(BaseModel):
    id: str
    api_id: str
    api_name: Optional[str] = None
    anomaly_type: str
    severity: str
    baseline_value: float
    observed_value: float
    deviation_percent: float
    details: str
    timestamp: datetime


class MonitoringOverviewResponse(BaseModel):
    api_id: str
    api_name: str
    current_status: str
    uptime_percentage_24h: float
    avg_latency_ms_24h: float
    p95_latency_ms_24h: float
    total_checks_24h: int
    failed_checks_24h: int
    last_check_time: Optional[datetime]
    metrics: List[MetricPoint] = []
