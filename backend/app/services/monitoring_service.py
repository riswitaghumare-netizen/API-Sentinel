import time
from datetime import datetime, timezone
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.api import APITarget, HealthStatus
from app.models.monitoring import MonitoringConfig, MonitoringMetric
from app.models.alert import AlertType, AlertSeverity
from app.services.alert_service import AlertService
from app.services.anomaly_service import AnomalyService
from app.core.ssrf import validate_target_url


class MonitoringService:
    @staticmethod
    async def perform_health_check(db: AsyncSession, api: APITarget) -> MonitoringMetric:
        """
        Executes an active health & latency probe against an authorized API target.
        """
        base_url = api.base_url
        is_safe, ssrf_msg = validate_target_url(base_url)
        if not is_safe:
            metric = MonitoringMetric(
                api_id=api.id,
                timestamp=datetime.now(timezone.utc),
                is_available=False,
                status_code=0,
                response_time_ms=0.0,
                headers_intact=False,
                tls_valid=False,
                error_message=f"SSRF Safety block: {ssrf_msg}",
            )
            db.add(metric)
            api.health_status = HealthStatus.DOWN
            await db.commit()
            return metric

        # Determine timeout config
        timeout = 5.0
        if api.monitoring_config:
            timeout = api.monitoring_config.timeout_seconds

        start_time = time.perf_counter()
        is_available = False
        status_code = 0
        response_time_ms = 0.0
        headers_intact = False
        tls_valid = True
        error_msg = None

        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
                resp = await client.get(base_url)
                duration = (time.perf_counter() - start_time) * 1000.0
                response_time_ms = round(duration, 1)
                status_code = resp.status_code
                
                # Check status code
                expected_statuses = [200, 201, 204, 301, 302, 401, 403]
                if api.monitoring_config and api.monitoring_config.expected_status_codes:
                    expected_statuses = api.monitoring_config.expected_status_codes

                is_available = status_code in expected_statuses or status_code < 500
                headers = {k.lower(): v for k, v in resp.headers.items()}
                headers_intact = "x-content-type-options" in headers or "strict-transport-security" in headers

        except httpx.RequestError as exc:
            duration = (time.perf_counter() - start_time) * 1000.0
            response_time_ms = round(duration, 1)
            is_available = False
            status_code = 0
            error_msg = f"Connection failed: {str(exc)}"

        metric = MonitoringMetric(
            api_id=api.id,
            timestamp=datetime.now(timezone.utc),
            is_available=is_available,
            status_code=status_code,
            response_time_ms=response_time_ms,
            headers_intact=headers_intact,
            tls_valid=tls_valid,
            error_message=error_msg,
        )
        db.add(metric)

        # Update API Target state
        api.last_monitored_at = datetime.now(timezone.utc)
        if not is_available:
            api.health_status = HealthStatus.DOWN
            await AlertService.create_alert(
                db=db,
                api_id=api.id,
                title=f"API Target Downtime Detected ({api.name})",
                alert_type=AlertType.API_DOWNTIME,
                severity=AlertSeverity.CRITICAL,
                description=f"Health probe to '{base_url}' failed. Status: {status_code}. Error: {error_msg or 'Non-responsive'}",
                recommended_action="Verify web server process, container health, and upstream routing.",
            )
        elif response_time_ms > 2000.0:
            api.health_status = HealthStatus.DEGRADED
        else:
            api.health_status = HealthStatus.HEALTHY

        await db.commit()

        # Run anomaly analysis
        await AnomalyService.analyze_metrics_for_anomalies(db, api.id)
        return metric
