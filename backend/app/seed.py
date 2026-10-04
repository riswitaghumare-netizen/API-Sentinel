import asyncio
from datetime import datetime, timezone, timedelta
from app.core.database import AsyncSessionLocal, init_db
from app.core.security import get_password_hash
from app.core.rbac import Role
from app.core.encryption import encrypt_secret, mask_secret
from app.models.user import User
from app.models.organization import Organization, Project
from app.models.api import (
    APITarget,
    APIEndpoint,
    APICredential,
    APIEnvironment,
    RiskClassification,
    MonitoringStatus,
    HealthStatus,
    AuthType,
)
from app.models.monitoring import MonitoringConfig, MonitoringMetric
from app.models.scan import Scan, ScanStatus, ScanProfileType
from app.models.vulnerability import (
    ScanFinding,
    FindingEvidence,
    FindingComment,
    VulnerabilitySeverity,
    VulnerabilityConfidence,
    VulnerabilityStatus,
)
from app.models.alert import Alert, AlertType, AlertSeverity, AlertStatus, NotificationChannel
from app.models.audit import AuditLog
from sqlalchemy import select


async def seed_database():
    """Initializes schema and populates initial enterprise demonstration data."""
    await init_db()

    async with AsyncSessionLocal() as db:
        # Check if already seeded
        user_check = await db.execute(select(User))
        if user_check.scalars().first():
            return

        print("[*] Seeding API Sentinel initial demonstration database...")

        # 1. Organizations & Projects
        org = Organization(
            name="Sentinel Cyber Defense Corp",
            slug="sentinel-cyber",
            description="Enterprise API Security Operations & Vulnerability Management",
        )
        db.add(org)
        await db.flush()

        proj = Project(
            organization_id=org.id,
            name="Payment & Customer Platform",
            slug="payment-customer-platform",
            description="Core payment processing and customer management API services",
        )
        db.add(proj)
        await db.flush()

        # 2. Users
        admin_user = User(
            email="admin@sentinel.sec",
            hashed_password=get_password_hash("SentinelAdmin2026!"),
            full_name="Alex Mercer (SecOps Lead)",
            role=Role.SUPER_ADMIN,
            is_active=True,
            is_verified=True,
            organization_id=org.id,
        )
        analyst_user = User(
            email="analyst@sentinel.sec",
            hashed_password=get_password_hash("AnalystPass2026!"),
            full_name="Elena Rostova (Security Analyst)",
            role=Role.SECURITY_ANALYST,
            is_active=True,
            is_verified=True,
            organization_id=org.id,
        )
        dev_user = User(
            email="dev@sentinel.sec",
            hashed_password=get_password_hash("DevPass2026!"),
            full_name="David Chen (Lead Backend Dev)",
            role=Role.DEVELOPER,
            is_active=True,
            is_verified=True,
            organization_id=org.id,
        )
        db.add_all([admin_user, analyst_user, dev_user])
        await db.flush()

        # 3. API Target 1: Local Demo Vulnerable API
        demo_api = APITarget(
            project_id=proj.id,
            name="FinTech Payments API (Demo Lab)",
            description="Production-representative financial transactions and customer profile API service.",
            base_url="http://localhost:8001",
            environment=APIEnvironment.STAGING,
            owner="David Chen",
            team="Payments Engineering",
            tags=["financial", "payments", "pci-scope", "v2-gateway"],
            technology="Python / FastAPI / PostgreSQL",
            version="v2.4.0",
            monitoring_status=MonitoringStatus.ENABLED,
            risk_classification=RiskClassification.HIGH,
            security_score=68.5,
            health_status=HealthStatus.HEALTHY,
            last_scanned_at=datetime.now(timezone.utc) - timedelta(hours=2),
            last_monitored_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        )
        db.add(demo_api)
        await db.flush()

        # API Target 2: Customer Identity Service
        auth_api = APITarget(
            project_id=proj.id,
            name="Customer Identity & Auth Service",
            description="OAuth2 and user authentication token exchange gateway.",
            base_url="http://localhost:8001",
            environment=APIEnvironment.PRODUCTION,
            owner="Elena Rostova",
            team="Identity Architecture",
            tags=["oauth2", "identity", "jwt", "zero-trust"],
            technology="Node.js / Express / Redis",
            version="v3.1.2",
            monitoring_status=MonitoringStatus.ENABLED,
            risk_classification=RiskClassification.CRITICAL,
            security_score=88.0,
            health_status=HealthStatus.HEALTHY,
            last_scanned_at=datetime.now(timezone.utc) - timedelta(hours=6),
            last_monitored_at=datetime.now(timezone.utc) - timedelta(minutes=2),
        )
        db.add(auth_api)
        await db.flush()

        # 4. API Endpoints
        endpoints = [
            APIEndpoint(
                api_id=demo_api.id,
                path="/api/v1/users",
                method="GET",
                summary="List Customer Accounts",
                description="Returns paginated customer profiles.",
                is_authenticated=True,
                auth_type=AuthType.BEARER_TOKEN,
                tags=["users"],
            ),
            APIEndpoint(
                api_id=demo_api.id,
                path="/api/v1/users/{id}",
                method="GET",
                summary="Get Customer Details by ID",
                description="Retrieves sensitive customer profile and billing details.",
                parameters=[{"name": "id", "in": "path", "required": True, "type": "string"}],
                is_authenticated=True,
                auth_type=AuthType.BEARER_TOKEN,
                tags=["users"],
            ),
            APIEndpoint(
                api_id=demo_api.id,
                path="/api/v1/orders/{id}",
                method="GET",
                summary="Retrieve Financial Order Details",
                description="Fetches order status and transaction amount.",
                parameters=[{"name": "id", "in": "path", "required": True, "type": "string"}],
                is_authenticated=True,
                auth_type=AuthType.BEARER_TOKEN,
                tags=["orders"],
            ),
            APIEndpoint(
                api_id=demo_api.id,
                path="/api/v1/orders",
                method="POST",
                summary="Submit New Payment Order",
                description="Processes new credit card order.",
                is_authenticated=True,
                auth_type=AuthType.API_KEY,
                tags=["orders"],
            ),
            APIEndpoint(
                api_id=demo_api.id,
                path="/api/v1/admin/debug",
                method="GET",
                summary="Internal Runtime Diagnostics",
                description="Undocumented endpoint dumping system runtime metadata.",
                is_authenticated=False,
                auth_type=AuthType.NONE,
                tags=["internal"],
            ),
            APIEndpoint(
                api_id=demo_api.id,
                path="/api/v1/echo",
                method="POST",
                summary="Payload Reflection Test",
                description="Echoes JSON input back to caller.",
                is_authenticated=False,
                auth_type=AuthType.NONE,
                tags=["utilities"],
            ),
        ]
        db.add_all(endpoints)
        await db.flush()

        # 5. Encrypted Credentials
        cred1 = APICredential(
            api_id=demo_api.id,
            auth_type=AuthType.BEARER_TOKEN,
            key_name="Staging Service Account JWT",
            header_name="Authorization",
            encrypted_secret=encrypt_secret("eyJhGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo_token_secret"),
            masked_preview=mask_secret("eyJhGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo_token_secret"),
        )
        cred2 = APICredential(
            api_id=demo_api.id,
            auth_type=AuthType.API_KEY,
            key_name="Gateway Secret Key",
            header_name="X-API-Key",
            encrypted_secret=encrypt_secret("sentinel_live_key_993847291847192"),
            masked_preview=mask_secret("sentinel_live_key_993847291847192"),
        )
        db.add_all([cred1, cred2])

        # 6. Monitoring Configs & 24h Metrics
        mon1 = MonitoringConfig(api_id=demo_api.id, interval_minutes=15, is_active=True)
        mon2 = MonitoringConfig(api_id=auth_api.id, interval_minutes=15, is_active=True)
        db.add_all([mon1, mon2])

        # Seed 24h of realistic metrics
        now = datetime.now(timezone.utc)
        for i in range(24, 0, -1):
            ts = now - timedelta(hours=i)
            # Normal fluctuation around 140ms with a slight bump
            latency = 120.0 + (i % 7) * 15.0 + (25.0 if i == 5 else 0.0)
            db.add(
                MonitoringMetric(
                    api_id=demo_api.id,
                    timestamp=ts,
                    is_available=True,
                    status_code=200,
                    response_time_ms=round(latency, 1),
                    headers_intact=False,
                    tls_valid=True,
                )
            )
            db.add(
                MonitoringMetric(
                    api_id=auth_api.id,
                    timestamp=ts,
                    is_available=True,
                    status_code=200,
                    response_time_ms=round(85.0 + (i % 5) * 8.0, 1),
                    headers_intact=True,
                    tls_valid=True,
                )
            )

        # 7. Initial Completed Scan
        scan1 = Scan(
            api_id=demo_api.id,
            profile_type=ScanProfileType.STANDARD,
            profile_name="Standard Security Baseline Scan",
            status=ScanStatus.COMPLETED,
            start_time=now - timedelta(hours=2, minutes=5),
            end_time=now - timedelta(hours=2),
            duration_seconds=14.8,
            total_requests=42,
            endpoints_tested=6,
            critical_count=1,
            high_count=2,
            medium_count=2,
            low_count=2,
            info_count=0,
            scanner_modules_executed=[
                "HeaderScanner",
                "CORScanner",
                "TLSScanner",
                "RateLimitScanner",
                "InformationDisclosureScanner",
                "OpenAPIScanner",
                "AuthenticationScanner",
                "SecurityPolicyScanner",
            ],
            initiated_by_user_id=admin_user.id,
        )
        db.add(scan1)
        await db.flush()

        # 8. Seed Findings & Evidence
        f1 = ScanFinding(
            scan_id=scan1.id,
            api_id=demo_api.id,
            endpoint_id=endpoints[4].id,  # /api/v1/admin/debug
            title="Missing Authentication on Internal Diagnostic Endpoint",
            severity=VulnerabilitySeverity.CRITICAL,
            cvss_score=9.1,
            risk_score=9.4,
            confidence=VulnerabilityConfidence.CERTAIN,
            http_method="GET",
            affected_endpoint_path="/api/v1/admin/debug",
            description="The administrative diagnostics route returns full runtime configuration and database connection parameters to unauthenticated callers.",
            risk_explanation="Exposing internal environment variables and server state allows unauthorized parties to compromise infrastructure and credentials.",
            remediation="Enforce strict role-based access control or completely remove internal debug routes in staging and production builds.",
            references=["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
            owasp_category="API2:2023 Broken Authentication",
            cwe_id="CWE-306",
            status=VulnerabilityStatus.OPEN,
            scanner_name="AuthenticationScanner",
            assignee_id=dev_user.id,
            due_date=now + timedelta(days=3),
        )
        db.add(f1)
        await db.flush()

        db.add(
            FindingEvidence(
                finding_id=f1.id,
                response_status=200,
                response_body_snippet='{"debug_mode": true, "db_host": "postgres-prod.internal", "runtime": "Python 3.13"}',
                redacted_proof="Sent unauthenticated GET to /api/v1/admin/debug. Server returned HTTP 200 OK with internal runtime environment details.",
                curl_command="curl -i http://localhost:8001/api/v1/admin/debug",
            )
        )

        f2 = ScanFinding(
            scan_id=scan1.id,
            api_id=demo_api.id,
            endpoint_id=endpoints[1].id,  # /api/v1/users/{id}
            title="Potential Broken Object-Level Authorization (BOLA)",
            severity=VulnerabilitySeverity.HIGH,
            cvss_score=8.2,
            risk_score=8.6,
            confidence=VulnerabilityConfidence.HIGH,
            http_method="GET",
            affected_endpoint_path="/api/v1/users/{id}",
            description="Sequential user ID iteration returns distinct customer account records without verifying caller authorization against the requested ID.",
            risk_explanation="Attackers can enumerate sequential user IDs to harvest private customer personally identifiable information (PII).",
            remediation="Verify that the authenticated token subject owns or has explicit permission to read the requested user ID.",
            references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
            owasp_category="API1:2023 Broken Object Level Authorization",
            cwe_id="CWE-639",
            status=VulnerabilityStatus.IN_REVIEW,
            scanner_name="AuthorizationScanner",
            assignee_id=analyst_user.id,
            due_date=now + timedelta(days=5),
        )
        db.add(f2)
        await db.flush()

        db.add(
            FindingEvidence(
                finding_id=f2.id,
                response_status=200,
                response_body_snippet='{"user_id": 2, "name": "Jane Smith", "email": "jane@example.com"}',
                redacted_proof="Sequential IDs /users/1 and /users/2 both returned HTTP 200 with distinct customer payloads.",
                curl_command="curl -H 'Authorization: Bearer [REDACTED_TOKEN]' http://localhost:8001/api/v1/users/2",
            )
        )

        f3 = ScanFinding(
            scan_id=scan1.id,
            api_id=demo_api.id,
            endpoint_id=endpoints[0].id,
            title="Insecure Credentialed CORS Configuration",
            severity=VulnerabilitySeverity.HIGH,
            cvss_score=7.8,
            risk_score=8.1,
            confidence=VulnerabilityConfidence.CERTAIN,
            http_method="OPTIONS",
            affected_endpoint_path="/api/v1/users",
            description="The endpoint reflects arbitrary Origin headers with 'Access-Control-Allow-Credentials: true'.",
            risk_explanation="Allows third-party websites to make authenticated cross-origin browser requests and steal private JSON response data.",
            remediation="Specify explicit trusted client origin domains in CORS configuration instead of mirroring the incoming Origin header.",
            references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
            owasp_category="API8:2023 Security Misconfiguration",
            cwe_id="CWE-942",
            status=VulnerabilityStatus.OPEN,
            scanner_name="CORScanner",
            assignee_id=dev_user.id,
        )
        db.add(f3)
        await db.flush()

        f4 = ScanFinding(
            scan_id=scan1.id,
            api_id=demo_api.id,
            endpoint_id=endpoints[0].id,
            title="Missing Rate Limiting & Throttling Controls",
            severity=VulnerabilitySeverity.MEDIUM,
            cvss_score=5.3,
            risk_score=5.6,
            confidence=VulnerabilityConfidence.HIGH,
            http_method="GET",
            affected_endpoint_path="/api/v1/users",
            description="The API accepted rapid sequential requests without returning rate-limiting headers or 429 status codes.",
            risk_explanation="Enables brute force, credential stuffing, and volumetric denial-of-service.",
            remediation="Implement rate limiting (e.g. 100 req/min per IP/token) and return HTTP 429 Too Many Requests with Retry-After header.",
            references=["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
            owasp_category="API4:2023 Unrestricted Resource Consumption",
            cwe_id="CWE-770",
            status=VulnerabilityStatus.OPEN,
            scanner_name="RateLimitScanner",
        )
        db.add(f4)
        await db.flush()

        # 9. Comments & Alerts
        db.add(
            FindingComment(
                finding_id=f1.id,
                user_id=analyst_user.id,
                comment_text="Verified during vulnerability triage. The /admin/debug route was left active during the last release. High priority fix needed.",
                created_at=now - timedelta(hours=1, minutes=30),
            )
        )
        db.add(
            Alert(
                api_id=demo_api.id,
                title="Critical Security Finding: Missing Auth on /admin/debug",
                alert_type=AlertType.CRITICAL_VULNERABILITY,
                severity=AlertSeverity.CRITICAL,
                status=AlertStatus.TRIGGERED,
                description="Administrative diagnostics route leaks environment variables to unauthenticated callers.",
                dedup_key=f"{demo_api.id}:CRITICAL_VULNERABILITY:Missing Auth",
                recommended_action="Decommission /admin/debug endpoint or place behind superadmin VPN gateway.",
                created_at=now - timedelta(hours=2),
            )
        )
        db.add(
            NotificationChannel(
                name="Security Operations Slack Webhook",
                channel_type="WEBHOOK",
                destination_url="https://hooks.slack.com/services/T000/B000/XXXX",
                filter_min_severity=AlertSeverity.HIGH,
                is_active=True,
            )
        )

        # 10. Audit Logs
        db.add(
            AuditLog(
                user_id=admin_user.id,
                user_email=admin_user.email,
                action="INITIAL_PLATFORM_SETUP",
                resource_type="SYSTEM",
                status="SUCCESS",
                ip_address="127.0.0.1",
                details={"message": "API Sentinel initial database initialization complete."},
                created_at=now - timedelta(hours=3),
            )
        )

        await db.commit()
        print("[+] Seed completed successfully! SuperAdmin: admin@sentinel.sec (Pass: SentinelAdmin2026!)")


if __name__ == "__main__":
    asyncio.run(seed_database())
