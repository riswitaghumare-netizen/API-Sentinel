from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from app.core.database import get_db
from app.core.rbac import Permission
from app.models.user import User
from app.models.audit import AuditLog
from app.schemas.base import ApiResponse
from app.api.deps import get_current_user, require_permission

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs & Timeline"])


class AuditLogResponse(BaseModel):
    id: str
    user_id: Optional[str]
    user_email: Optional[str]
    action: str
    resource_type: str
    resource_id: Optional[str]
    status: str
    ip_address: Optional[str]
    details: dict
    created_at: datetime


@router.get("", response_model=ApiResponse[List[AuditLogResponse]])
async def list_audit_logs(
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    current_user: User = Depends(require_permission(Permission.AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Lists security audit timeline records."""
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(200)

    conditions = []
    if action:
        conditions.append(AuditLog.action == action)
    if resource_type:
        conditions.append(AuditLog.resource_type == resource_type)

    if conditions:
        stmt = stmt.where(and_(*conditions))

    logs = (await db.execute(stmt)).scalars().all()

    return ApiResponse(
        data=[
            AuditLogResponse(
                id=l.id,
                user_id=l.user_id,
                user_email=l.user_email,
                action=l.action,
                resource_type=l.resource_type,
                resource_id=l.resource_id,
                status=l.status,
                ip_address=l.ip_address,
                details=l.details or {},
                created_at=l.created_at,
            )
            for l in logs
        ]
    )
