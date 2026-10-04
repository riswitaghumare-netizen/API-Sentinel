from typing import Optional
from datetime import datetime
from pydantic import BaseModel
from app.models.alert import AlertType, AlertSeverity, AlertStatus


class AlertUpdateRequest(BaseModel):
    status: Optional[AlertStatus] = None
    assigned_user_id: Optional[str] = None


class AlertResponse(BaseModel):
    id: str
    api_id: str
    api_name: Optional[str] = None
    title: str
    alert_type: AlertType
    severity: AlertSeverity
    status: AlertStatus
    description: str
    evidence: Optional[str] = None
    recommended_action: Optional[str] = None
    assigned_user_id: Optional[str] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime


class NotificationChannelCreate(BaseModel):
    name: str
    channel_type: str = "WEBHOOK"
    destination_url: str
    filter_min_severity: AlertSeverity = AlertSeverity.MEDIUM


class NotificationChannelResponse(BaseModel):
    id: str
    name: str
    channel_type: str
    destination_url: Optional[str]
    is_active: bool
    filter_min_severity: AlertSeverity
    created_at: datetime
