import math
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from app.models.monitoring import MonitoringMetric, AnomalyEvent
from app.models.alert import AlertType, AlertSeverity
from app.services.alert_service import AlertService


class AnomalyService:
    @staticmethod
    async def analyze_metrics_for_anomalies(db: AsyncSession, api_id: str) -> List[AnomalyEvent]:
        """
        Analyzes the last 24 hours of monitoring metrics to establish a baseline
        and detect latency spikes (> 3 std deviations) or error rate surges.
        """
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(hours=24)

        stmt = select(MonitoringMetric).where(
            and_(
                MonitoringMetric.api_id == api_id,
                MonitoringMetric.timestamp >= start_time,
            )
        ).order_by(MonitoringMetric.timestamp.asc())
        result = await db.execute(stmt)
        metrics = result.scalars().all()

        if len(metrics) < 5:
            # Insufficient baseline data
            return []

        latencies = [m.response_time_ms for m in metrics]
        avg_latency = sum(latencies) / len(latencies)
        variance = sum((x - avg_latency) ** 2 for x in latencies) / len(latencies)
        std_dev = math.sqrt(variance)

        recent_metric = metrics[-1]
        detected_anomalies = []

        # 1. Latency Spike Detection (Current response time > avg + 2.5 * std_dev)
        if std_dev > 10.0 and recent_metric.response_time_ms > (avg_latency + 2.5 * std_dev) and recent_metric.response_time_ms > 1000.0:
            dev_pct = ((recent_metric.response_time_ms - avg_latency) / max(avg_latency, 1.0)) * 100.0
            anomaly = AnomalyEvent(
                api_id=api_id,
                anomaly_type="LATENCY_SPIKE",
                severity="HIGH",
                baseline_value=round(avg_latency, 1),
                observed_value=round(recent_metric.response_time_ms, 1),
                deviation_percent=round(dev_pct, 1),
                details=f"Response time spiked to {recent_metric.response_time_ms:.1f}ms (Baseline: {avg_latency:.1f}ms ± {std_dev:.1f}ms, +{dev_pct:.1f}% deviation).",
                timestamp=now,
            )
            db.add(anomaly)
            detected_anomalies.append(anomaly)

            await AlertService.create_alert(
                db=db,
                api_id=api_id,
                title=f"Significant Latency Degradation Detected (+{dev_pct:.0f}%)",
                alert_type=AlertType.LATENCY_DEGRADATION,
                severity=AlertSeverity.HIGH,
                description=anomaly.details,
                recommended_action="Investigate backend database queries, connection pool saturation, or upstream service degradation.",
            )

        # 2. Error Rate Surge Detection in last 10 samples
        recent_window = metrics[-10:]
        error_count = sum(1 for m in recent_window if not m.is_available or m.status_code >= 500)
        recent_error_rate = (error_count / len(recent_window)) * 100.0

        if recent_error_rate >= 40.0:
            anomaly = AnomalyEvent(
                api_id=api_id,
                anomaly_type="ERROR_RATE_SURGE",
                severity="CRITICAL",
                baseline_value=5.0,
                observed_value=recent_error_rate,
                deviation_percent=recent_error_rate,
                details=f"Error rate reached {recent_error_rate:.1f}% across recent monitoring intervals ({error_count}/{len(recent_window)} failures).",
                timestamp=now,
            )
            db.add(anomaly)
            detected_anomalies.append(anomaly)

            await AlertService.create_alert(
                db=db,
                api_id=api_id,
                title="Critical Error Rate Spike Detected",
                alert_type=AlertType.ERROR_RATE_SPIKE,
                severity=AlertSeverity.CRITICAL,
                description=anomaly.details,
                recommended_action="Check application logs immediately for unhandled exceptions or service crashes.",
            )

        if detected_anomalies:
            await db.commit()

        return detected_anomalies
