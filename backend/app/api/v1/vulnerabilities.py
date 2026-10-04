from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload
from app.core.database import get_db
from app.core.rbac import Permission
from app.core.exceptions import NotFoundException
from app.models.user import User
from app.models.vulnerability import (
    ScanFinding,
    FindingEvidence,
    FindingComment,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from app.schemas.base import ApiResponse
from app.schemas.scan import (
    ScanFindingResponse,
    FindingEvidenceResponse,
    FindingUpdateRequest,
    FindingCommentCreate,
    FindingCommentResponse,
)
from app.api.deps import get_current_user, require_permission
from app.services.audit_service import AuditService

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Management"])


@router.get("", response_model=ApiResponse[List[ScanFindingResponse]])
async def list_vulnerabilities(
    api_id: Optional[str] = None,
    severity: Optional[VulnerabilitySeverity] = None,
    status: Optional[VulnerabilityStatus] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists security findings across all APIs or filtered by API, severity, or status."""
    stmt = (
        select(ScanFinding)
        .options(
            selectinload(ScanFinding.api_target),
            selectinload(ScanFinding.evidence),
            selectinload(ScanFinding.assignee),
        )
        .order_by(ScanFinding.risk_score.desc(), ScanFinding.created_at.desc())
    )

    conditions = []
    if api_id:
        conditions.append(ScanFinding.api_id == api_id)
    if severity:
        conditions.append(ScanFinding.severity == severity)
    if status:
        conditions.append(ScanFinding.status == status)

    if conditions:
        stmt = stmt.where(and_(*conditions))

    findings = (await db.execute(stmt)).scalars().all()

    return ApiResponse(
        data=[
            ScanFindingResponse(
                id=f.id,
                scan_id=f.scan_id,
                api_id=f.api_id,
                api_name=f.api_target.name if f.api_target else "API Target",
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
                assignee_name=f.assignee.full_name if f.assignee else None,
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
            for f in findings
        ]
    )


@router.get("/{vuln_id}", response_model=ApiResponse[ScanFindingResponse])
async def get_vulnerability_detail(
    vuln_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves deep investigation details for a specific vulnerability finding."""
    stmt = (
        select(ScanFinding)
        .where(ScanFinding.id == vuln_id)
        .options(
            selectinload(ScanFinding.api_target),
            selectinload(ScanFinding.evidence),
            selectinload(ScanFinding.assignee),
            selectinload(ScanFinding.comments).selectinload(FindingComment.author),
        )
    )
    result = await db.execute(stmt)
    f = result.scalars().first()
    if not f:
        raise NotFoundException("Vulnerability Finding", vuln_id)

    comments_data = [
        FindingCommentResponse(
            id=c.id,
            user_id=c.user_id,
            user_name=c.author.full_name if c.author else "Analyst",
            comment_text=c.comment_text,
            created_at=c.created_at,
        )
        for c in f.comments
    ]

    return ApiResponse(
        data=ScanFindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            api_id=f.api_id,
            api_name=f.api_target.name if f.api_target else "API Target",
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
            assignee_name=f.assignee.full_name if f.assignee else None,
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
            comments=comments_data,
        )
    )


@router.put("/{vuln_id}", response_model=ApiResponse[dict])
async def update_vulnerability(
    vuln_id: str,
    req: FindingUpdateRequest,
    current_user: User = Depends(require_permission(Permission.VULN_UPDATE)),
    db: AsyncSession = Depends(get_db),
):
    """Updates vulnerability status, assignment, or remediation due date."""
    stmt = select(ScanFinding).where(ScanFinding.id == vuln_id)
    f = (await db.execute(stmt)).scalars().first()
    if not f:
        raise NotFoundException("Vulnerability Finding", vuln_id)

    old_status = f.status.value
    if req.status:
        f.status = req.status
    if req.assignee_id is not None:
        f.assignee_id = req.assignee_id
    if req.due_date is not None:
        f.due_date = req.due_date

    f.updated_at = datetime.now(timezone.utc)
    await db.commit()

    await AuditService.log_event(
        db=db,
        action="VULNERABILITY_STATUS_UPDATED",
        resource_type="VULNERABILITY",
        resource_id=vuln_id,
        user_id=current_user.id,
        user_email=current_user.email,
        details={"old_status": old_status, "new_status": f.status.value, "title": f.title},
    )

    return ApiResponse(data={"message": "Vulnerability finding updated successfully."})


@router.post("/{vuln_id}/comments", response_model=ApiResponse[FindingCommentResponse])
async def add_finding_comment(
    vuln_id: str,
    req: FindingCommentCreate,
    current_user: User = Depends(require_permission(Permission.VULN_COMMENT)),
    db: AsyncSession = Depends(get_db),
):
    """Adds a triage comment to the vulnerability investigation thread."""
    stmt = select(ScanFinding).where(ScanFinding.id == vuln_id)
    f = (await db.execute(stmt)).scalars().first()
    if not f:
        raise NotFoundException("Vulnerability Finding", vuln_id)

    comment = FindingComment(
        finding_id=vuln_id,
        user_id=current_user.id,
        comment_text=req.comment_text,
        created_at=datetime.now(timezone.utc),
    )
    db.add(comment)
    await db.commit()
    await db.refresh(comment)

    return ApiResponse(
        data=FindingCommentResponse(
            id=comment.id,
            user_id=comment.user_id,
            user_name=current_user.full_name,
            comment_text=comment.comment_text,
            created_at=comment.created_at,
        )
    )
