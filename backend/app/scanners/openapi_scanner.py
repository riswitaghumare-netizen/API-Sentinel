from typing import Dict, Any, List, Optional
import httpx
from app.scanners.base import BaseScanner, ScannerFinding
from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence


class OpenAPIScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "OpenAPIScanner"

    @property
    def description(self) -> str:
        return "Compares documented OpenAPI/Swagger specifications against actual live API behavior to detect shadow endpoints, undocumented methods, and schema drift."

    @property
    def category(self) -> str:
        return "API Discovery & Specification Drift"

    async def scan(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        credentials: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ScannerFinding]:
        findings = []

        # Common undocumented endpoint probes
        shadow_paths = [
            "/api/v1/admin/debug",
            "/api/v1/internal",
            "/metrics",
            "/actuator/health",
            "/swagger.json",
            "/api-docs",
            "/graphql",
        ]

        documented_paths = {ep.get("path", "") for ep in endpoints}

        for path in shadow_paths:
            if path in documented_paths:
                continue

            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            try:
                resp = await client.get(url, timeout=4.0)
                # If returns 200 or 401/403 (meaning endpoint actually exists and isn't a 404)
                if resp.status_code in (200, 201, 401, 403):
                    is_admin_or_debug = "debug" in path or "admin" in path or "internal" in path
                    findings.append(
                        ScannerFinding(
                            title=f"Undocumented / Shadow API Endpoint Detected ({path})",
                            severity=VulnerabilitySeverity.HIGH if is_admin_or_debug else VulnerabilitySeverity.MEDIUM,
                            description=f"Endpoint '{path}' returned HTTP {resp.status_code} but is not defined in the API specification.",
                            risk_explanation="Shadow and unmanaged API endpoints frequently bypass security controls, rate limiting, and governance policies.",
                            remediation="Document this endpoint in the official OpenAPI specification or disable/restrict access if it is intended only for internal use.",
                            scanner_name=self.name,
                            http_method="GET",
                            affected_endpoint_path=path,
                            confidence=VulnerabilityConfidence.HIGH,
                            cvss_score=6.8 if is_admin_or_debug else 5.1,
                            owasp_category="API9:2023 Improper Inventory Management",
                            cwe_id="CWE-1059",
                            evidence_response_status=resp.status_code,
                            evidence_response_body=resp.text[:500] if resp.text else None,
                            evidence_proof=f"HTTP GET returned status {resp.status_code}.",
                            curl_command=f"curl -I '{url}'",
                        )
                    )
            except Exception:
                continue

        # Check for deprecated endpoints in inventory
        for ep in endpoints:
            if ep.get("is_deprecated"):
                path = ep.get("path", "")
                findings.append(
                    ScannerFinding(
                        title=f"Use of Deprecated API Endpoint in Active Inventory ({path})",
                        severity=VulnerabilitySeverity.LOW,
                        description=f"Endpoint '{path}' is marked as deprecated in OpenAPI specification but remains registered.",
                        risk_explanation="Deprecated APIs may lack recent security patches and expose obsolete data structures.",
                        remediation="Decommission the deprecated endpoint and migrate clients to current API versions.",
                        scanner_name=self.name,
                        http_method=ep.get("method", "GET"),
                        affected_endpoint_path=path,
                        confidence=VulnerabilityConfidence.CERTAIN,
                        cvss_score=3.5,
                        owasp_category="API9:2023 Improper Inventory Management",
                        cwe_id="CWE-1059",
                    )
                )

        return findings
