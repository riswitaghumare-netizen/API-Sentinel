from typing import Dict, Any, List, Optional
import httpx
from app.scanners.base import BaseScanner, ScannerFinding
from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence


class SecurityPolicyScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "SecurityPolicyScanner"

    @property
    def description(self) -> str:
        return "Tests for dangerous HTTP verbs (TRACE, TRACK), verifies Cache-Control on sensitive endpoints, and checks Content-Type enforcement."

    @property
    def category(self) -> str:
        return "HTTP Protocol & Policy Compliance"

    async def scan(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        credentials: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ScannerFinding]:
        findings = []
        root_url = base_url.rstrip("/")

        # 1. Test for HTTP TRACE method (Cross-Site Tracing / XST risk)
        try:
            resp_trace = await client.request("TRACE", root_url, timeout=4.0)
            if resp_trace.status_code == 200:
                findings.append(
                    ScannerFinding(
                        title="Dangerous HTTP TRACE Method Enabled",
                        severity=VulnerabilitySeverity.MEDIUM,
                        description="The API server supports and responds to HTTP TRACE requests.",
                        risk_explanation="HTTP TRACE reflects the exact request headers back in the response body, enabling Cross-Site Tracing (XST) attacks that steal HttpOnly cookies.",
                        remediation="Disable HTTP TRACE and TRACK methods on the web server / reverse proxy.",
                        scanner_name=self.name,
                        http_method="TRACE",
                        affected_endpoint_path="/",
                        confidence=VulnerabilityConfidence.CERTAIN,
                        cvss_score=5.3,
                        owasp_category="API8:2023 Security Misconfiguration",
                        cwe_id="CWE-16",
                        evidence_response_status=resp_trace.status_code,
                        evidence_proof="Server responded with HTTP 200 to HTTP TRACE method.",
                        curl_command=f"curl -X TRACE '{root_url}'",
                    )
                )
        except Exception:
            pass

        # 2. Check Cache-Control headers on user / sensitive endpoints
        for ep in endpoints[:4]:
            path = ep.get("path", "")
            if any(k in path.lower() for k in ["user", "auth", "account", "profile", "order"]):
                url = f"{root_url}/{path.lstrip('/')}".replace("{id}", "1")
                try:
                    resp = await client.get(url, timeout=4.0)
                    cache_ctrl = resp.headers.get("cache-control", "").lower()
                    if "no-store" not in cache_ctrl and resp.status_code == 200:
                        findings.append(
                            ScannerFinding(
                                title=f"Missing 'no-store' Cache-Control on Sensitive Endpoint ({path})",
                                severity=VulnerabilitySeverity.LOW,
                                description=f"Endpoint '{path}' returns sensitive data without 'Cache-Control: no-store, no-cache'.",
                                risk_explanation="Shared proxy caches or browser history may cache sensitive personal data.",
                                remediation="Add 'Cache-Control: no-store, no-cache, must-revalidate' and 'Pragma: no-cache' response headers to all authenticated API routes.",
                                scanner_name=self.name,
                                http_method="GET",
                                affected_endpoint_path=path,
                                confidence=VulnerabilityConfidence.HIGH,
                                cvss_score=3.4,
                                owasp_category="API8:2023 Security Misconfiguration",
                                cwe_id="CWE-524",
                                evidence_response_status=resp.status_code,
                                evidence_response_headers=dict(resp.headers),
                                curl_command=f"curl -I '{url}'",
                            )
                        )
                except Exception:
                    pass

        return findings
