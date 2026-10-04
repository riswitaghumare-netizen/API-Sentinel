from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import selectinload
from app.core.database import get_db
from app.core.rbac import Role, Permission
from app.core.exceptions import NotFoundException, ValidationException
from app.core.ssrf import validate_target_url
from app.core.encryption import encrypt_secret, mask_secret
from app.models.user import User
from app.models.organization import Project
from app.models.api import (
    APITarget,
    APIEndpoint,
    APICredential,
    APIEnvironment,
    RiskClassification,
    MonitoringStatus,
    HealthStatus,
)
from app.models.monitoring import MonitoringConfig
from app.models.vulnerability import ScanFinding, VulnerabilityStatus
from app.schemas.base import ApiResponse
from app.schemas.api import (
    APICreate,
    APIUpdate,
    APICredentialCreate,
    APICredentialResponse,
    APIEndpointResponse,
    APIDetailResponse,
    APIListItemResponse,
    OpenAPIImportRequest,
)
from app.api.deps import get_current_user, require_permission
from app.services.openapi_parser import OpenAPIParser
from app.services.audit_service import AuditService

router = APIRouter(prefix="/apis", tags=["APIs & Inventory"])


@router.get("", response_model=ApiResponse[List[APIListItemResponse]])
async def list_apis(
    environment: Optional[APIEnvironment] = None,
    risk: Optional[RiskClassification] = None,
    monitoring: Optional[MonitoringStatus] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists registered APIs with multi-faceted filtering and vulnerability counters."""
    stmt = select(APITarget).options(
        selectinload(APITarget.endpoints),
        selectinload(APITarget.vulnerabilities),
    )

    conditions = []
    if environment:
        conditions.append(APITarget.environment == environment)
    if risk:
        conditions.append(APITarget.risk_classification == risk)
    if monitoring:
        conditions.append(APITarget.monitoring_status == monitoring)
    if search:
        search_pattern = f"%{search}%"
        conditions.append(or_(APITarget.name.ilike(search_pattern), APITarget.base_url.ilike(search_pattern)))

    if conditions:
        stmt = stmt.where(and_(*conditions))

    stmt = stmt.order_by(APITarget.created_at.desc())
    apis = (await db.execute(stmt)).scalars().all()

    items = []
    for a in apis:
        open_vulns = sum(
            1
            for v in a.vulnerabilities
            if v.status not in (VulnerabilityStatus.FALSE_POSITIVE, VulnerabilityStatus.REMEDIATED)
        )
        items.append(
            APIListItemResponse(
                id=a.id,
                project_id=a.project_id,
                name=a.name,
                description=a.description,
                base_url=a.base_url,
                environment=a.environment,
                owner=a.owner,
                team=a.team,
                tags=a.tags or [],
                technology=a.technology,
                version=a.version,
                monitoring_status=a.monitoring_status,
                risk_classification=a.risk_classification,
                security_score=a.security_score,
                health_status=a.health_status,
                endpoints_count=len(a.endpoints),
                open_vulnerabilities_count=open_vulns,
                last_scanned_at=a.last_scanned_at,
                last_monitored_at=a.last_monitored_at,
                created_at=a.created_at,
            )
        )

    return ApiResponse(data=items)


@router.post("", response_model=ApiResponse[APIDetailResponse])
async def create_api(
    req: APICreate,
    request: Request,
    current_user: User = Depends(require_permission(Permission.API_CREATE)),
    db: AsyncSession = Depends(get_db),
):
    """Registers a new authorized API target with credentials and initial monitoring config."""
    # 1. Validate SSRF Safety
    is_safe, msg = validate_target_url(req.base_url)
    if not is_safe:
        raise ValidationException(f"Base URL rejected by SSRF protection policy: {msg}")

    # Determine project ID
    proj_id = req.project_id
    if not proj_id:
        proj_stmt = select(Project)
        proj = (await db.execute(proj_stmt)).scalars().first()
        if not proj:
            raise ValidationException("Please create a Project before registering an API.")
        proj_id = proj.id

    new_api = APITarget(
        project_id=proj_id,
        name=req.name,
        description=req.description,
        base_url=req.base_url.rstrip("/"),
        environment=req.environment,
        owner=req.owner or current_user.full_name,
        team=req.team or "Core Security",
        tags=req.tags or [],
        technology=req.technology,
        version=req.version,
        risk_classification=req.risk_classification,
        monitoring_status=req.monitoring_status,
        security_score=100.0,
        health_status=HealthStatus.UNKNOWN,
        created_at=datetime.now(timezone.utc),
    )
    db.add(new_api)
    await db.flush()

    # 2. Add Encrypted Credentials if provided
    if req.credentials:
        for cred in req.credentials:
            encrypted_val = encrypt_secret(cred.secret_value)
            masked_val = mask_secret(cred.secret_value)
            api_cred = APICredential(
                api_id=new_api.id,
                auth_type=cred.auth_type,
                key_name=cred.key_name,
                header_name=cred.header_name or "Authorization",
                encrypted_secret=encrypted_val,
                masked_preview=masked_val,
            )
            db.add(api_cred)

    # 3. Create default Monitoring Config
    mon_config = MonitoringConfig(
        api_id=new_api.id,
        interval_minutes=15,
        is_active=(req.monitoring_status == MonitoringStatus.ENABLED),
        timeout_seconds=5.0,
        expected_status_codes=[200, 201, 204, 301, 302, 401, 403],
        latency_threshold_ms=1500.0,
        consecutive_failures_alert=2,
    )
    db.add(mon_config)

    await db.commit()

    # Log audit
    client_ip = request.client.host if request.client else "127.0.0.1"
    await AuditService.log_event(
        db=db,
        action="API_REGISTERED",
        resource_type="API",
        resource_id=new_api.id,
        user_id=current_user.id,
        user_email=current_user.email,
        ip_address=client_ip,
        details={"name": new_api.name, "base_url": new_api.base_url, "environment": new_api.environment.value},
    )

    return await get_api_detail(new_api.id, current_user, db)


@router.get("/{api_id}", response_model=ApiResponse[APIDetailResponse])
async def get_api_detail(
    api_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves comprehensive details, endpoints, credentials, and vulnerability stats for an API."""
    stmt = (
        select(APITarget)
        .where(APITarget.id == api_id)
        .options(
            selectinload(APITarget.endpoints),
            selectinload(APITarget.credentials),
            selectinload(APITarget.vulnerabilities),
        )
    )
    result = await db.execute(stmt)
    api = result.scalars().first()
    if not api:
        raise NotFoundException("API Target", api_id)

    # Count vulns by severity
    active_vulns = [
        v for v in api.vulnerabilities if v.status not in (VulnerabilityStatus.FALSE_POSITIVE, VulnerabilityStatus.REMEDIATED)
    ]
    crit_count = sum(1 for v in active_vulns if v.severity.value == "CRITICAL")
    high_count = sum(1 for v in active_vulns if v.severity.value == "HIGH")
    med_count = sum(1 for v in active_vulns if v.severity.value == "MEDIUM")
    low_count = sum(1 for v in active_vulns if v.severity.value == "LOW")
    info_count = sum(1 for v in active_vulns if v.severity.value == "INFORMATIONAL")

    detail = APIDetailResponse(
        id=api.id,
        project_id=api.project_id,
        name=api.name,
        description=api.description,
        base_url=api.base_url,
        environment=api.environment,
        owner=api.owner,
        team=api.team,
        tags=api.tags or [],
        technology=api.technology,
        version=api.version,
        monitoring_status=api.monitoring_status,
        risk_classification=api.risk_classification,
        security_score=api.security_score,
        health_status=api.health_status,
        endpoints_count=len(api.endpoints),
        open_vulnerabilities_count=len(active_vulns),
        last_scanned_at=api.last_scanned_at,
        last_monitored_at=api.last_monitored_at,
        created_at=api.created_at,
        critical_vulns=crit_count,
        high_vulns=high_count,
        medium_vulns=med_count,
        low_vulns=low_count,
        info_vulns=info_count,
        endpoints=[
            APIEndpointResponse(
                id=ep.id,
                path=ep.path,
                method=ep.method,
                summary=ep.summary,
                description=ep.description,
                parameters=ep.parameters or [],
                request_body_schema=ep.request_body_schema or {},
                responses_schema=ep.responses_schema or {},
                is_authenticated=ep.is_authenticated,
                auth_type=ep.auth_type,
                is_deprecated=ep.is_deprecated,
                tags=ep.tags or [],
                last_tested_at=ep.last_tested_at,
            )
            for ep in api.endpoints
        ],
        credentials=[
            APICredentialResponse(
                id=c.id,
                auth_type=c.auth_type,
                key_name=c.key_name,
                header_name=c.header_name,
                masked_preview=c.masked_preview,
                created_at=c.created_at,
            )
            for c in api.credentials
        ],
    )
    return ApiResponse(data=detail)


@router.post("/import-openapi", response_model=ApiResponse[APIDetailResponse])
async def import_openapi_specification(
    req: OpenAPIImportRequest,
    project_id: Optional[str] = None,
    current_user: User = Depends(require_permission(Permission.API_CREATE)),
    db: AsyncSession = Depends(get_db),
):
    """Imports OpenAPI 3.x or Swagger 2.0 specification and automatically registers API + all endpoints."""
    try:
        spec_data = OpenAPIParser.parse_spec(req.spec_content)
        api_meta, discovered_endpoints = OpenAPIParser.extract_inventory(spec_data)
    except Exception as e:
        raise ValidationException(f"Failed to parse OpenAPI specification: {str(e)}")

    base_url = req.base_url_override or api_meta.get("base_url", "http://localhost:8000")
    is_safe, msg = validate_target_url(base_url)
    if not is_safe:
        raise ValidationException(f"Base URL in spec rejected by SSRF protection: {msg}")

    # Determine project ID
    proj_id = project_id
    if not proj_id:
        proj_stmt = select(Project)
        proj = (await db.execute(proj_stmt)).scalars().first()
        proj_id = proj.id

    new_api = APITarget(
        project_id=proj_id,
        name=api_meta.get("name", "Imported API Specification"),
        description=api_meta.get("description", "Imported via OpenAPI specification."),
        base_url=base_url.rstrip("/"),
        environment=APIEnvironment.DEVELOPMENT,
        owner=current_user.full_name,
        team="Security Architecture",
        tags=["openapi-import", api_meta.get("version", "v1.0")],
        technology="OpenAPI / REST",
        version=api_meta.get("version", "v1.0.0"),
        monitoring_status=MonitoringStatus.ENABLED,
        security_score=100.0,
        health_status=HealthStatus.UNKNOWN,
        openapi_spec_raw=req.spec_content,
        created_at=datetime.now(timezone.utc),
    )
    db.add(new_api)
    await db.flush()

    # Save discovered endpoints
    for ep in discovered_endpoints:
        endpoint_rec = APIEndpoint(
            api_id=new_api.id,
            path=ep["path"],
            method=ep["method"],
            summary=ep["summary"],
            description=ep["description"],
            parameters=ep["parameters"],
            request_body_schema=ep["request_body_schema"],
            responses_schema=ep["responses_schema"],
            is_authenticated=ep["is_authenticated"],
            auth_type=ep["auth_type"],
            is_deprecated=ep["is_deprecated"],
            tags=ep["tags"],
        )
        db.add(endpoint_rec)

    # Add default monitoring config
    mon_config = MonitoringConfig(
        api_id=new_api.id,
        interval_minutes=15,
        is_active=True,
    )
    db.add(mon_config)

    await db.commit()

    await AuditService.log_event(
        db=db,
        action="OPENAPI_SPEC_IMPORTED",
        resource_type="API",
        resource_id=new_api.id,
        user_id=current_user.id,
        user_email=current_user.email,
        details={"name": new_api.name, "endpoints_count": len(discovered_endpoints)},
    )

    return await get_api_detail(new_api.id, current_user, db)


@router.delete("/{api_id}", response_model=ApiResponse[dict])
async def delete_api(
    api_id: str,
    current_user: User = Depends(require_permission(Permission.API_DELETE)),
    db: AsyncSession = Depends(get_db),
):
    """Deletes an API target and all its scans, findings, and metrics."""
    stmt = select(APITarget).where(APITarget.id == api_id)
    api = (await db.execute(stmt)).scalars().first()
    if not api:
        raise NotFoundException("API Target", api_id)

    api_name = api.name
    await db.delete(api)
    await db.commit()

    await AuditService.log_event(
        db=db,
        action="API_DELETED",
        resource_type="API",
        resource_id=api_id,
        user_id=current_user.id,
        user_email=current_user.email,
        details={"api_name": api_name},
    )

    return ApiResponse(data={"message": f"API '{api_name}' deleted successfully."})
