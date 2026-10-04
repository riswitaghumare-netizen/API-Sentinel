from typing import List, Optional
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload
from app.core.database import get_db
from app.core.rbac import Permission
from app.core.exceptions import NotFoundException
from app.models.user import User
from app.models.api import APITarget
from app.models.monitoring import MonitoringConfig, MonitoringMetric, AnomalyEvent
from app.schemas.base import ApiResponse
from app.schemas.monitoring import (
    MonitoringConfigResponse,
    MonitoringConfigUpdate,
    MetricPoint,
    AnomalyResponse,
    MonitoringOverviewResponse,
)
from app.api.deps import get_current_user, require_permission
from app.services.monitoring_service import MonitoringService

router = APIRouter(prefix="/monitoring", tags=["Continuous Monitoring"])


@router.get("/overview", response_model=ApiResponse[List[MonitoringOverviewResponse]])
async def get_monitoring_overview(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns real-time health, uptime %, and latency percentiles across all registered APIs."""
    stmt = select(APITarget).options(
        selectinload(APITarget.monitoring_metrics),
    )
    apis = (await db.execute(stmt)).scalars().all()

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)

    items = []
    for a in apis:
        metrics_24h = [m for m in a.monitoring_metrics if m.timestamp >= cutoff]
        total_checks = len(metrics_24h)
        successful_checks = sum(1 for m in metrics_24h if m.is_available)
        failed_checks = total_checks - successful_checks
        uptime = (successful_checks / total_checks * 100.0) if total_checks > 0 else 100.0

        latencies = sorted([m.response_time_ms for m in metrics_24h])
        avg_latency = (sum(latencies) / len(latencies)) if latencies else 0.0
        p95_idx = int(len(latencies) * 0.95)
        p95_latency = latencies[p95_idx] if latencies else avg_latency

        # Last 20 metric points
        recent_pts = sorted(a.monitoring_metrics, key=lambda x: x.timestamp)[-20:]

        items.append(
            MonitoringOverviewResponse(
                api_id=a.id,
                api_name=a.name,
                current_status=a.health_status.value,
                uptime_percentage_24h=round(uptime, 2),
                avg_latency_ms_24h=round(avg_latency, 1),
                p95_latency_ms_24h=round(p95_latency, 1),
                total_checks_24h=total_checks,
                failed_checks_24h=failed_checks,
                last_check_time=a.last_monitored_at,
                metrics=[
                    MetricPoint(
                        timestamp=m.timestamp,
                        is_available=m.is_available,
                        status_code=m.status_code,
                        response_time_ms=m.response_time_ms,
                        headers_intact=m.headers_intact,
                        tls_valid=m.tls_valid,
                        error_message=m.error_message,
                    )
                    for m in recent_pts
                ],
            )
        )

    return ApiResponse(data=items)


@router.get("/apis/{api_id}", response_model=ApiResponse[MonitoringOverviewResponse])
async def get_api_monitoring_detail(
    api_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves 24-hour time series metrics and health status for a specific API target."""
    stmt = (
        select(APITarget)
        .where(APITarget.id == api_id)
        .options(selectinload(APITarget.monitoring_metrics))
    )
    api = (await db.execute(stmt)).scalars().first()
    if not api:
        raise NotFoundException("API Target", api_id)

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    metrics_24h = [m for m in api.monitoring_metrics if m.timestamp >= cutoff]

    total_checks = len(metrics_24h)
    successful_checks = sum(1 for m in metrics_24h if m.is_available)
    failed_checks = total_checks - successful_checks
    uptime = (successful_checks / total_checks * 100.0) if total_checks > 0 else 100.0

    latencies = sorted([m.response_time_ms for m in metrics_24h])
    avg_latency = (sum(latencies) / len(latencies)) if latencies else 0.0
    p95_idx = int(len(latencies) * 0.95)
    p95_latency = latencies[p95_idx] if latencies else avg_latency

    recent_pts = sorted(api.monitoring_metrics, key=lambda x: x.timestamp)[-50:]

    return ApiResponse(
        data=MonitoringOverviewResponse(
            api_id=api.id,
            api_name=api.name,
            current_status=api.health_status.value,
            uptime_percentage_24h=round(uptime, 2),
            avg_latency_ms_24h=round(avg_latency, 1),
            p95_latency_ms_24h=round(p95_latency, 1),
            total_checks_24h=total_checks,
            failed_checks_24h=failed_checks,
            last_check_time=api.last_monitored_at,
            metrics=[
                MetricPoint(
                    timestamp=m.timestamp,
                    is_available=m.is_available,
                    status_code=m.status_code,
                    response_time_ms=m.response_time_ms,
                    headers_intact=m.headers_intact,
                    tls_valid=m.tls_valid,
                    error_message=m.error_message,
                )
                for m in recent_pts
            ],
        )
    )


@router.post("/apis/{api_id}/check", response_model=ApiResponse[MetricPoint])
async def trigger_health_check(
    api_id: str,
    current_user: User = Depends(require_permission(Permission.MONITORING_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Triggers an immediate on-demand health & latency probe against the target API."""
    stmt = (
        select(APITarget)
        .where(APITarget.id == api_id)
        .options(selectinload(APITarget.monitoring_config))
    )
    api = (await db.execute(stmt)).scalars().first()
    if not api:
        raise NotFoundException("API Target", api_id)

    metric = await MonitoringService.perform_health_check(db, api)

    return ApiResponse(
        data=MetricPoint(
            timestamp=metric.timestamp,
            is_available=metric.is_available,
            status_code=metric.status_code,
            response_time_ms=metric.response_time_ms,
            headers_intact=metric.headers_intact,
            tls_valid=metric.tls_valid,
            error_message=metric.error_message,
        )
    )


@router.get("/anomalies", response_model=ApiResponse[List[AnomalyResponse]])
async def list_anomalies(
    api_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists statistically detected performance, error rate, and availability anomalies."""
    stmt = select(AnomalyEvent).order_by(AnomalyEvent.timestamp.desc())
    if api_id:
        stmt = stmt.where(AnomalyEvent.api_id == api_id)

    anomalies = (await db.execute(stmt)).scalars().all()

    # Load API names
    api_stmt = select(APITarget)
    all_apis = {a.id: a.name for a in (await db.execute(api_stmt)).scalars().all()}

    return ApiResponse(
        data=[
            AnomalyResponse(
                id=a.id,
                api_id=a.api_id,
                api_name=all_apis.get(a.api_id, "API Target"),
                anomaly_type=a.anomaly_type,
                severity=a.severity,
                baseline_value=a.baseline_value,
                observed_value=a.observed_value,
                deviation_percent=a.deviation_percent,
                details=a.details,
                timestamp=a.timestamp,
            )
            for a in anomalies
        ]
    )
