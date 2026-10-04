from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload
from app.core.database import get_db
from app.core.rbac import Permission
from app.core.exceptions import NotFoundException
from app.models.user import User
from app.models.api import APITarget
from app.models.alert import Alert, AlertSeverity, AlertStatus, NotificationChannel
from app.schemas.base import ApiResponse
from app.schemas.alert import (
    AlertResponse,
    AlertUpdateRequest,
    NotificationChannelCreate,
    NotificationChannelResponse,
)
from app.api.deps import get_current_user, require_permission
from app.services.audit_service import AuditService

router = APIRouter(prefix="/alerts", tags=["Alerts & Notifications"])


@router.get("", response_model=ApiResponse[List[AlertResponse]])
async def list_alerts(
    api_id: Optional[str] = None,
    severity: Optional[AlertSeverity] = None,
    status: Optional[AlertStatus] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists security alerts with severity and status filters."""
    stmt = select(Alert).options(selectinload(Alert.api_target)).order_by(Alert.created_at.desc())

    conditions = []
    if api_id:
        conditions.append(Alert.api_id == api_id)
    if severity:
        conditions.append(Alert.severity == severity)
    if status:
        conditions.append(Alert.status == status)

    if conditions:
        stmt = stmt.where(and_(*conditions))

    alerts = (await db.execute(stmt)).scalars().all()

    return ApiResponse(
        data=[
            AlertResponse(
                id=a.id,
                api_id=a.api_id,
                api_name=a.api_target.name if a.api_target else "API Target",
                title=a.title,
                alert_type=a.alert_type,
                severity=a.severity,
                status=a.status,
                description=a.description,
                evidence=a.evidence,
                recommended_action=a.recommended_action,
                assigned_user_id=a.assigned_user_id,
                resolved_at=a.resolved_at,
                created_at=a.created_at,
            )
            for a in alerts
        ]
    )


@router.put("/{alert_id}", response_model=ApiResponse[dict])
async def update_alert(
    alert_id: str,
    req: AlertUpdateRequest,
    current_user: User = Depends(require_permission(Permission.ALERT_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Updates status (Acknowledged / Resolved) or assignee of an alert."""
    stmt = select(Alert).where(Alert.id == alert_id)
    alert = (await db.execute(stmt)).scalars().first()
    if not alert:
        raise NotFoundException("Alert", alert_id)

    if req.status:
        alert.status = req.status
        if req.status == AlertStatus.RESOLVED:
            alert.resolved_at = datetime.now(timezone.utc)
    if req.assigned_user_id is not None:
        alert.assigned_user_id = req.assigned_user_id

    await db.commit()

    await AuditService.log_event(
        db=db,
        action="ALERT_STATUS_UPDATED",
        resource_type="ALERT",
        resource_id=alert_id,
        user_id=current_user.id,
        user_email=current_user.email,
        details={"status": alert.status.value, "title": alert.title},
    )

    return ApiResponse(data={"message": "Alert status updated successfully."})


@router.get("/channels", response_model=ApiResponse[List[NotificationChannelResponse]])
async def list_notification_channels(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists configured outbound webhook notification channels."""
    stmt = select(NotificationChannel).order_by(NotificationChannel.created_at.desc())
    channels = (await db.execute(stmt)).scalars().all()

    return ApiResponse(
        data=[
            NotificationChannelResponse(
                id=c.id,
                name=c.name,
                channel_type=c.channel_type,
                destination_url=c.destination_url,
                is_active=c.is_active,
                filter_min_severity=c.filter_min_severity,
                created_at=c.created_at,
            )
            for c in channels
        ]
    )


@router.post("/channels", response_model=ApiResponse[NotificationChannelResponse])
async def create_notification_channel(
    req: NotificationChannelCreate,
    current_user: User = Depends(require_permission(Permission.ALERT_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Registers a new outbound webhook channel."""
    channel = NotificationChannel(
        name=req.name,
        channel_type=req.channel_type,
        destination_url=req.destination_url,
        filter_min_severity=req.filter_min_severity,
        is_active=True,
    )
    db.add(channel)
    await db.commit()
    await db.refresh(channel)

    return ApiResponse(
        data=NotificationChannelResponse(
            id=channel.id,
            name=channel.name,
            channel_type=channel.channel_type,
            destination_url=channel.destination_url,
            is_active=channel.is_active,
            filter_min_severity=channel.filter_min_severity,
            created_at=channel.created_at,
        )
    )
