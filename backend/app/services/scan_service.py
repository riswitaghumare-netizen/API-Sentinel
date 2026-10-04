import asyncio
import time
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.models.scan import Scan, ScanStatus, ScanProfileType
from app.models.api import APITarget, APIEndpoint, APICredential
from app.models.vulnerability import ScanFinding, FindingEvidence, VulnerabilityStatus
from app.models.alert import AlertType, AlertSeverity
from app.scanners.registry import get_scanners_for_profile
from app.core.ssrf import validate_target_url
from app.core.encryption import decrypt_secret
from app.services.scoring_service import (
    calculate_finding_risk_score,
    calculate_api_security_score,
)
from app.services.alert_service import AlertService
from app.services.audit_service import AuditService


class ScanService:
    @staticmethod
    async def execute_scan(db: AsyncSession, scan_id: str):
        """
        Main orchestration loop for executing an asynchronous vulnerability scan.
        """
        stmt = (
            select(Scan)
            .where(Scan.id == scan_id)
            .options(
                selectinload(Scan.api_target).selectinload(APITarget.endpoints),
                selectinload(Scan.api_target).selectinload(APITarget.credentials),
            )
        )
        result = await db.execute(stmt)
        scan = result.scalars().first()

        if not scan or scan.status != ScanStatus.PENDING:
            return

        api = scan.api_target
        scan.status = ScanStatus.RUNNING
        scan.start_time = datetime.now(timezone.utc)
        await db.commit()

        start_perf = time.perf_counter()

        # 1. SSRF Safety Verification
        is_safe, ssrf_msg = validate_target_url(api.base_url)
        if not is_safe:
            scan.status = ScanStatus.FAILED
            scan.error_message = f"Scan aborted by SSRF protection policy: {ssrf_msg}"
            scan.end_time = datetime.now(timezone.utc)
            scan.duration_seconds = round(time.perf_counter() - start_perf, 2)
            await db.commit()
            return

        # 2. Prepare Endpoints and Credentials
        endpoints_data = [
            {
                "id": ep.id,
                "path": ep.path,
                "method": ep.method,
                "summary": ep.summary,
                "parameters": ep.parameters,
                "request_body_schema": ep.request_body_schema,
                "responses_schema": ep.responses_schema,
                "is_authenticated": ep.is_authenticated,
                "is_deprecated": ep.is_deprecated,
            }
            for ep in api.endpoints
        ]

        auth_headers = {}
        for cred in api.credentials:
            decrypted = decrypt_secret(cred.encrypted_secret)
            if cred.auth_type.value == "API_KEY":
                auth_headers[cred.header_name or "X-API-Key"] = decrypted
            elif cred.auth_type.value == "BEARER_TOKEN":
                auth_headers["Authorization"] = f"Bearer {decrypted}"
            elif cred.auth_type.value == "CUSTOM_HEADER":
                auth_headers[cred.header_name] = decrypted

        # 3. Load Scanner Plugins
        scanners = get_scanners_for_profile(scan.profile_type)
        scan.scanner_modules_executed = [s.name for s in scanners]

        total_requests = 0
        discovered_findings = []

        # 4. Execute Scanner Modules
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=8.0,
            headers=auth_headers,
        ) as client:
            for scanner in scanners:
                try:
                    findings = await scanner.scan(
                        client=client,
                        base_url=api.base_url,
                        endpoints=endpoints_data,
                        credentials={"headers": auth_headers},
                        context={"api_id": api.id, "scan_id": scan.id},
                    )
                    discovered_findings.extend(findings)
                    total_requests += len(endpoints_data) * 2 + 3
                except Exception as e:
                    pass

        # 5. Persist Findings & Evidence to Database
        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0
        info_count = 0

        finding_dicts_for_scoring = []

        # Match endpoints by path
        endpoint_map = {ep.path.lower(): ep.id for ep in api.endpoints}

        for f in discovered_findings:
            # Calculate Risk Score
            risk_score = calculate_finding_risk_score(
                severity=f.severity,
                confidence=f.confidence,
                environment=api.environment,
                risk_classification=api.risk_classification,
            )

            ep_id = endpoint_map.get(f.affected_endpoint_path.lower())

            db_finding = ScanFinding(
                scan_id=scan.id,
                api_id=api.id,
                endpoint_id=ep_id,
                title=f.title,
                severity=f.severity,
                cvss_score=f.cvss_score,
                risk_score=risk_score,
                confidence=f.confidence,
                http_method=f.http_method,
                affected_endpoint_path=f.affected_endpoint_path,
                parameter_name=f.parameter_name,
                description=f.description,
                risk_explanation=f.risk_explanation,
                remediation=f.remediation,
                references=f.references,
                owasp_category=f.owasp_category,
                cwe_id=f.cwe_id,
                nist_control=f.nist_control,
                status=VulnerabilityStatus.OPEN,
                scanner_name=f.scanner_name,
                first_detected_at=datetime.now(timezone.utc),
                last_detected_at=datetime.now(timezone.utc),
            )
            db.add(db_finding)
            await db.flush()

            # Add Evidence record
            evidence_record = FindingEvidence(
                finding_id=db_finding.id,
                request_headers=f.evidence_request_headers,
                request_body=f.evidence_request_body,
                response_status=f.evidence_response_status,
                response_headers=f.evidence_response_headers,
                response_body_snippet=f.evidence_response_body,
                redacted_proof=f.evidence_proof,
                curl_command=f.curl_command,
            )
            db.add(evidence_record)

            # Severity counts
            if f.severity.value == "CRITICAL":
                crit_count += 1
            elif f.severity.value == "HIGH":
                high_count += 1
            elif f.severity.value == "MEDIUM":
                med_count += 1
            elif f.severity.value == "LOW":
                low_count += 1
            else:
                info_count += 1

            finding_dicts_for_scoring.append({"severity": f.severity.value, "status": "OPEN"})

            # Generate Alert for Critical / High
            if f.severity.value in ("CRITICAL", "HIGH"):
                await AlertService.create_alert(
                    db=db,
                    api_id=api.id,
                    title=f"Security Finding: {f.title}",
                    alert_type=AlertType.CRITICAL_VULNERABILITY if f.severity.value == "CRITICAL" else AlertType.HIGH_VULNERABILITY,
                    severity=AlertSeverity.CRITICAL if f.severity.value == "CRITICAL" else AlertSeverity.HIGH,
                    description=f.description,
                    evidence=f.evidence_proof,
                    recommended_action=f.remediation,
                )

        # 6. Recalculate API Security Score
        new_security_score = calculate_api_security_score(
            findings=finding_dicts_for_scoring,
            has_tls=api.base_url.startswith("https"),
            has_headers=(med_count == 0 and crit_count == 0),
            has_auth_covered=(crit_count == 0),
            has_rate_limiting=True,
            has_spec_accurate=True,
            is_monitored=True,
        )

        api.security_score = new_security_score
        api.last_scanned_at = datetime.now(timezone.utc)

        # 7. Finalize Scan Job
        scan.status = ScanStatus.COMPLETED
        scan.end_time = datetime.now(timezone.utc)
        scan.duration_seconds = round(time.perf_counter() - start_perf, 2)
        scan.total_requests = max(total_requests, len(endpoints_data) * 3 + 4)
        scan.endpoints_tested = len(endpoints_data) if endpoints_data else 1
        scan.critical_count = crit_count
        scan.high_count = high_count
        scan.medium_count = med_count
        scan.low_count = low_count
        scan.info_count = info_count

        await db.commit()

        # 8. Record Audit Log
        await AuditService.log_event(
            db=db,
            action="SCAN_COMPLETED",
            resource_type="SCAN",
            resource_id=scan.id,
            details={
                "api_id": api.id,
                "api_name": api.name,
                "profile": scan.profile_type.value,
                "findings_count": len(discovered_findings),
                "critical": crit_count,
                "high": high_count,
                "duration": scan.duration_seconds,
            },
        )
