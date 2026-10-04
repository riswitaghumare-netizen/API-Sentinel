from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.core.database import get_db
from app.models.user import User
from app.models.api import APITarget, MonitoringStatus, HealthStatus
from app.models.scan import Scan
from app.models.vulnerability import ScanFinding, VulnerabilityStatus
from app.models.alert import Alert, AlertStatus
from app.schemas.base import ApiResponse
from app.schemas.dashboard import (
    DashboardStatsResponse,
    SeverityDistribution,
    VulnerabilityTrendPoint,
    TopRiskAPI,
)
from app.api.deps import get_current_user

router = APIRouter(prefix="/dashboard", tags=["SOC Dashboard"])


@router.get("/stats", response_model=ApiResponse[DashboardStatsResponse])
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregates all top-level SOC statistics, trend lines, and risk distributions for the main dashboard."""
    # 1. Fetch APIs
    stmt_apis = select(APITarget).options(
        selectinload(APITarget.vulnerabilities),
        selectinload(APITarget.endpoints),
    )
    apis = (await db.execute(stmt_apis)).scalars().all()

    total_apis = len(apis)
    monitored_apis = sum(1 for a in apis if a.monitoring_status == MonitoringStatus.ENABLED)
    healthy_apis = sum(1 for a in apis if a.health_status == HealthStatus.HEALTHY)
    overall_availability = (healthy_apis / total_apis * 100.0) if total_apis > 0 else 100.0
    avg_score = (sum(a.security_score for a in apis) / total_apis) if total_apis > 0 else 100.0

    # 2. Fetch Findings
    stmt_findings = select(ScanFinding).options(selectinload(ScanFinding.api_target))
    all_findings = (await db.execute(stmt_findings)).scalars().all()
    active_findings = [
        f for f in all_findings if f.status not in (VulnerabilityStatus.FALSE_POSITIVE, VulnerabilityStatus.REMEDIATED)
    ]

    crit_count = sum(1 for f in active_findings if f.severity.value == "CRITICAL")
    high_count = sum(1 for f in active_findings if f.severity.value == "HIGH")
    med_count = sum(1 for f in active_findings if f.severity.value == "MEDIUM")
    low_count = sum(1 for f in active_findings if f.severity.value == "LOW")
    info_count = sum(1 for f in active_findings if f.severity.value == "INFORMATIONAL")

    # 3. Active Alerts
    stmt_alerts = select(Alert).where(Alert.status.in_([AlertStatus.TRIGGERED, AlertStatus.ACKNOWLEDGED]))
    active_alerts = len((await db.execute(stmt_alerts)).scalars().all())

    # 4. Top Risks
    top_risk_items = []
    for a in sorted(apis, key=lambda x: x.security_score):
        a_crit = sum(1 for v in a.vulnerabilities if v.severity.value == "CRITICAL" and v.status not in (VulnerabilityStatus.FALSE_POSITIVE, VulnerabilityStatus.REMEDIATED))
        a_high = sum(1 for v in a.vulnerabilities if v.severity.value == "HIGH" and v.status not in (VulnerabilityStatus.FALSE_POSITIVE, VulnerabilityStatus.REMEDIATED))
        top_risk_items.append(
            TopRiskAPI(
                id=a.id,
                name=a.name,
                environment=a.environment.value,
                security_score=a.security_score,
                critical_count=a_crit,
                high_count=a_high,
                risk_level=a.risk_classification.value,
            )
        )

    # 5. Recent Scans
    stmt_scans = select(Scan).options(selectinload(Scan.api_target)).order_by(Scan.created_at.desc()).limit(5)
    recent_scans_data = [
        {
            "id": s.id,
            "api_name": s.api_target.name if s.api_target else "API Target",
            "profile_name": s.profile_name,
            "status": s.status.value,
            "duration_seconds": s.duration_seconds,
            "critical_count": s.critical_count,
            "high_count": s.high_count,
            "medium_count": s.medium_count,
            "created_at": s.created_at.isoformat(),
        }
        for s in (await db.execute(stmt_scans)).scalars().all()
    ]

    # 6. 7-Day Vulnerability Trends
    now = datetime.now(timezone.utc)
    trends = []
    for i in range(6, -1, -1):
        day_date = now - timedelta(days=i)
        day_str = day_date.strftime("%b %d")
        
        # Count findings created on or before this day
        day_findings = [f for f in active_findings if f.created_at.date() <= day_date.date()]
        trends.append(
            VulnerabilityTrendPoint(
                date=day_str,
                critical=sum(1 for f in day_findings if f.severity.value == "CRITICAL"),
                high=sum(1 for f in day_findings if f.severity.value == "HIGH"),
                medium=sum(1 for f in day_findings if f.severity.value == "MEDIUM"),
                low=sum(1 for f in day_findings if f.severity.value == "LOW"),
            )
        )

    response = DashboardStatsResponse(
        total_apis=total_apis,
        monitored_apis=monitored_apis,
        critical_vulnerabilities=crit_count,
        high_vulnerabilities=high_count,
        open_findings=len(active_findings),
        average_security_score=round(avg_score, 1),
        overall_availability=round(overall_availability, 1),
        active_alerts=active_alerts,
        severity_distribution=SeverityDistribution(
            critical=crit_count,
            high=high_count,
            medium=med_count,
            low=low_count,
            informational=info_count,
        ),
        vulnerability_trends=trends,
        top_risks=top_risk_items[:5],
        recent_scans=recent_scans_data,
    )

    return ApiResponse(data=response)
