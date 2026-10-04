import asyncio
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.core.database import get_db, AsyncSessionLocal
from app.core.rbac import Role, Permission
from app.core.exceptions import NotFoundException, ValidationException
from app.models.user import User
from app.models.api import APITarget
from app.models.scan import Scan, ScanStatus, ScanProfileType
from app.models.vulnerability import ScanFinding
from app.schemas.base import ApiResponse
from app.schemas.scan import (
    ScanTriggerRequest,
    ScanResponse,
    ScanFindingResponse,
    FindingEvidenceResponse,
)
from app.api.deps import get_current_user, require_permission
from app.services.scan_service import ScanService
from app.services.audit_service import AuditService

router = APIRouter(prefix="/scans", tags=["Security Scans"])


async def run_scan_in_background(scan_id: str):
    """Background task runner for executing scans without blocking API requests."""
    async with AsyncSessionLocal() as session:
        try:
            await ScanService.execute_scan(session, scan_id)
        except Exception as e:
            stmt = select(Scan).where(Scan.id == scan_id)
            res = await session.execute(stmt)
            sc = res.scalars().first()
            if sc:
                sc.status = ScanStatus.FAILED
                sc.error_message = f"Execution error: {str(e)}"
                await session.commit()


@router.post("", response_model=ApiResponse[ScanResponse])
async def trigger_scan(
    api_id: str,
    req: ScanTriggerRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: User = Depends(require_permission(Permission.SCAN_START)),
    db: AsyncSession = Depends(get_db),
):
    """Triggers an authorized asynchronous vulnerability scan against an API target."""
    stmt = select(APITarget).where(APITarget.id == api_id)
    api = (await db.execute(stmt)).scalars().first()
    if not api:
        raise NotFoundException("API Target", api_id)

    # Check for already running scan on same target
    running_stmt = select(Scan).where(Scan.api_id == api_id, Scan.status == ScanStatus.RUNNING)
    already_running = (await db.execute(running_stmt)).scalars().first()
    if already_running:
        raise ValidationException("A security scan is already currently running against this API target.")

    profile_name_map = {
        ScanProfileType.QUICK: "Quick Health & Header Scan",
        ScanProfileType.STANDARD: "Standard Security Baseline Scan",
        ScanProfileType.DEEP: "Comprehensive Deep Scan",
        ScanProfileType.CUSTOM: "Custom Modular Scan",
    }

    new_scan = Scan(
        api_id=api.id,
        profile_type=req.profile_type,
        profile_name=profile_name_map.get(req.profile_type, "Security Scan"),
        status=ScanStatus.PENDING,
        initiated_by_user_id=current_user.id,
        created_at=datetime.now(timezone.utc),
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)

    # Dispatch to background task runner
    background_tasks.add_task(run_scan_in_background, new_scan.id)

    client_ip = request.client.host if request.client else "127.0.0.1"
    await AuditService.log_event(
        db=db,
        action="SCAN_STARTED",
        resource_type="SCAN",
        resource_id=new_scan.id,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=client_ip,
        details={"api_id": api.id, "api_name": api.name, "profile": req.profile_type.value},
    )

    return ApiResponse(
        data=ScanResponse(
            id=new_scan.id,
            api_id=new_scan.api_id,
            api_name=api.name,
            profile_type=new_scan.profile_type,
            profile_name=new_scan.profile_name,
            status=new_scan.status,
            start_time=new_scan.start_time,
            end_time=new_scan.end_time,
            duration_seconds=new_scan.duration_seconds,
            total_requests=new_scan.total_requests,
            endpoints_tested=new_scan.endpoints_tested,
            critical_count=new_scan.critical_count,
            high_count=new_scan.high_count,
            medium_count=new_scan.medium_count,
            low_count=new_scan.low_count,
            info_count=new_scan.info_count,
            scanner_modules_executed=new_scan.scanner_modules_executed or [],
            error_message=new_scan.error_message,
            created_at=new_scan.created_at,
            findings=[],
        )
    )


@router.get("", response_model=ApiResponse[List[ScanResponse]])
async def list_scans(
    api_id: Optional[str] = None,
    status: Optional[ScanStatus] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists historical and active scans."""
    stmt = (
        select(Scan)
        .options(selectinload(Scan.api_target))
        .order_by(Scan.created_at.desc())
    )
    if api_id:
        stmt = stmt.where(Scan.api_id == api_id)
    if status:
        stmt = stmt.where(Scan.status == status)

    scans = (await db.execute(stmt)).scalars().all()
    return ApiResponse(
        data=[
            ScanResponse(
                id=s.id,
                api_id=s.api_id,
                api_name=s.api_target.name if s.api_target else "API Target",
                profile_type=s.profile_type,
                profile_name=s.profile_name,
                status=s.status,
                start_time=s.start_time,
                end_time=s.end_time,
                duration_seconds=s.duration_seconds,
                total_requests=s.total_requests,
                endpoints_tested=s.endpoints_tested,
                critical_count=s.critical_count,
                high_count=s.high_count,
                medium_count=s.medium_count,
                low_count=s.low_count,
                info_count=s.info_count,
                scanner_modules_executed=s.scanner_modules_executed or [],
                error_message=s.error_message,
                created_at=s.created_at,
            )
            for s in scans
        ]
    )


@router.get("/{scan_id}", response_model=ApiResponse[ScanResponse])
async def get_scan_details(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Gets details and all findings discovered during a specific scan."""
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id)
        .options(
            selectinload(Scan.api_target),
            selectinload(Scan.findings).selectinload(ScanFinding.evidence),
        )
    )
    result = await db.execute(stmt)
    scan = result.scalars().first()
    if not scan:
        raise NotFoundException("Scan", scan_id)

    findings_resp = [
        ScanFindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            api_id=f.api_id,
            api_name=scan.api_target.name if scan.api_target else "API Target",
            endpoint_id=f.endpoint_id,
            title=f.title,
            severity=f.severity,
            cvss_score=f.cvss_score,
            risk_score=f.risk_score,
            confidence=f.confidence,
            http_method=f.http_method,
            affected_endpoint_path=f.affected_endpoint_path,
            parameter_name=f.parameter_name,
            description=f.description,
            risk_explanation=f.risk_explanation,
            remediation=f.remediation,
            references=f.references or [],
            owasp_category=f.owasp_category,
            cwe_id=f.cwe_id,
            nist_control=f.nist_control,
            status=f.status,
            scanner_name=f.scanner_name,
            assignee_id=f.assignee_id,
            due_date=f.due_date,
            first_detected_at=f.first_detected_at,
            last_detected_at=f.last_detected_at,
            created_at=f.created_at,
            evidence=FindingEvidenceResponse(
                id=f.evidence.id,
                request_headers=f.evidence.request_headers or {},
                request_body=f.evidence.request_body,
                response_status=f.evidence.response_status,
                response_headers=f.evidence.response_headers or {},
                response_body_snippet=f.evidence.response_body_snippet,
                redacted_proof=f.evidence.redacted_proof,
                curl_command=f.evidence.curl_command,
            )
            if f.evidence
            else None,
        )
        for f in scan.findings
    ]

    return ApiResponse(
        data=ScanResponse(
            id=scan.id,
            api_id=scan.api_id,
            api_name=scan.api_target.name if scan.api_target else "API Target",
            profile_type=scan.profile_type,
            profile_name=scan.profile_name,
            status=scan.status,
            start_time=scan.start_time,
            end_time=scan.end_time,
            duration_seconds=scan.duration_seconds,
            total_requests=scan.total_requests,
            endpoints_tested=scan.endpoints_tested,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            info_count=scan.info_count,
            scanner_modules_executed=scan.scanner_modules_executed or [],
            error_message=scan.error_message,
            created_at=scan.created_at,
            findings=findings_resp,
        )
    )
