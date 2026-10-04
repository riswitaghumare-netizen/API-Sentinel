from typing import List, Optional
from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.rbac import Permission
from app.core.exceptions import NotFoundException
from app.models.user import User
from app.models.report import SecurityReport, ReportFormat
from app.schemas.base import ApiResponse
from app.schemas.report import ReportGenerateRequest, ReportResponse
from app.api.deps import get_current_user, require_permission
from app.services.report_service import ReportService
from app.services.audit_service import AuditService

router = APIRouter(prefix="/reports", tags=["Security Reports"])


@router.post("/generate", response_model=ApiResponse[ReportResponse])
async def generate_report(
    req: ReportGenerateRequest,
    current_user: User = Depends(require_permission(Permission.REPORT_GENERATE)),
    db: AsyncSession = Depends(get_db),
):
    """Generates an executive or technical security report across APIs or for a specific target."""
    report = await ReportService.generate_security_report(
        db=db,
        title=req.title,
        scope=req.scope,
        target_id=req.target_id,
        report_format=req.report_format,
        user_id=current_user.id,
    )

    await AuditService.log_event(
        db=db,
        action="REPORT_GENERATED",
        resource_type="REPORT",
        resource_id=report.id,
        user_id=current_user.id,
        user_email=current_user.email,
        details={"title": report.title, "format": report.report_format.value},
    )

    return ApiResponse(
        data=ReportResponse(
            id=report.id,
            title=report.title,
            scope=report.scope,
            target_id=report.target_id,
            report_format=report.report_format,
            summary_data=report.summary_data,
            content_payload=report.content_payload,
            created_at=report.created_at,
        )
    )


@router.get("", response_model=ApiResponse[List[ReportResponse]])
async def list_reports(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists historical generated security reports."""
    stmt = select(SecurityReport).order_by(SecurityReport.created_at.desc())
    reports = (await db.execute(stmt)).scalars().all()

    return ApiResponse(
        data=[
            ReportResponse(
                id=r.id,
                title=r.title,
                scope=r.scope,
                target_id=r.target_id,
                report_format=r.report_format,
                summary_data=r.summary_data,
                created_at=r.created_at,
            )
            for r in reports
        ]
    )


@router.get("/{report_id}", response_model=ApiResponse[ReportResponse])
async def get_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves full report content payload and summary data."""
    stmt = select(SecurityReport).where(SecurityReport.id == report_id)
    report = (await db.execute(stmt)).scalars().first()
    if not report:
        raise NotFoundException("Security Report", report_id)

    return ApiResponse(
        data=ReportResponse(
            id=report.id,
            title=report.title,
            scope=report.scope,
            target_id=report.target_id,
            report_format=report.report_format,
            summary_data=report.summary_data,
            content_payload=report.content_payload,
            created_at=report.created_at,
        )
    )


@router.get("/{report_id}/download")
async def download_report_raw(
    report_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Directly downloads or previews report content in HTML, JSON, or CSV format."""
    stmt = select(SecurityReport).where(SecurityReport.id == report_id)
    report = (await db.execute(stmt)).scalars().first()
    if not report:
        raise NotFoundException("Security Report", report_id)

    content = report.content_payload or ""
    if report.report_format == ReportFormat.JSON:
        return Response(content=content, media_type="application/json")
    elif report.report_format == ReportFormat.CSV:
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=api_sentinel_report_{report.id}.csv"},
        )
    else:
        return Response(content=content, media_type="text/html")
