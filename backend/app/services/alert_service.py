from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from app.models.alert import Alert, AlertType, AlertSeverity, AlertStatus, NotificationChannel


class AlertService:
    @staticmethod
    async def create_alert(
        db: AsyncSession,
        api_id: str,
        title: str,
        alert_type: AlertType,
        severity: AlertSeverity,
        description: str,
        evidence: Optional[str] = None,
        recommended_action: Optional[str] = None,
        suppression_minutes: int = 60,
    ) -> Optional[Alert]:
        """
        Creates an alert with deduplication and suppression window to prevent notification flooding.
        """
        dedup_key = f"{api_id}:{alert_type.value}:{title[:50]}"
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=suppression_minutes)

        # Check for existing active or recent alert with same dedup_key
        stmt = select(Alert).where(
            and_(
                Alert.api_id == api_id,
                Alert.dedup_key == dedup_key,
                Alert.created_at >= cutoff_time,
                Alert.status.in_([AlertStatus.TRIGGERED, AlertStatus.ACKNOWLEDGED]),
            )
        )
        result = await db.execute(stmt)
        existing_alert = result.scalars().first()

        if existing_alert:
            # Suppress duplicate alert
            return None

        # Create new alert
        new_alert = Alert(
            api_id=api_id,
            title=title,
            alert_type=alert_type,
            severity=severity,
            status=AlertStatus.TRIGGERED,
            description=description,
            evidence=evidence,
            recommended_action=recommended_action,
            dedup_key=dedup_key,
            created_at=datetime.now(timezone.utc),
        )
        db.add(new_alert)
        await db.commit()
        await db.refresh(new_alert)

        # Asynchronously dispatch to active notification channels
        await AlertService._dispatch_notifications(db, new_alert)
        return new_alert

    @staticmethod
    async def _dispatch_notifications(db: AsyncSession, alert: Alert):
        """Sends alert payloads to registered webhook channels."""
        try:
            stmt = select(NotificationChannel).where(NotificationChannel.is_active == True)
            result = await db.execute(stmt)
            channels = result.scalars().all()

            payload = {
                "event": "api_security_alert",
                "alert_id": alert.id,
                "api_id": alert.api_id,
                "title": alert.title,
                "type": alert.alert_type.value,
                "severity": alert.severity.value,
                "description": alert.description,
                "timestamp": alert.created_at.isoformat(),
            }

            async with httpx.AsyncClient(timeout=3.0) as client:
                for ch in channels:
                    if ch.destination_url and ch.channel_type == "WEBHOOK":
                        try:
                            await client.post(ch.destination_url, json=payload)
                        except Exception:
                            pass
        except Exception:
            pass
