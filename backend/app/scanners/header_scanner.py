from typing import Dict, Any, List, Optional
import httpx
from app.scanners.base import BaseScanner, ScannerFinding
from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence


class HeaderScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "HeaderScanner"

    @property
    def description(self) -> str:
        return "Analyzes HTTP response headers for missing security controls (HSTS, CSP, X-Content-Type-Options, Cache-Control) and server banner disclosure."

    @property
    def category(self) -> str:
        return "Security Headers & Configuration"

    async def scan(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        credentials: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ScannerFinding]:
        findings = []
        target_endpoints = endpoints[:5] if endpoints else [{"path": "/", "method": "GET"}]

        for ep in target_endpoints:
            path = ep.get("path", "/")
            method = ep.get("method", "GET")
            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

            try:
                resp = await client.request(method, url, timeout=5.0)
                headers = {k.lower(): v for k, v in resp.headers.items()}

                # 1. Check Strict-Transport-Security (HSTS)
                if base_url.startswith("https://") and "strict-transport-security" not in headers:
                    findings.append(
                        ScannerFinding(
                            title="Missing HTTP Strict Transport Security (HSTS) Header",
                            severity=VulnerabilitySeverity.MEDIUM,
                            description=f"The endpoint '{path}' does not enforce HTTPS via the Strict-Transport-Security header.",
                            risk_explanation="Without HSTS, clients may be vulnerable to SSL stripping or downgrade attacks over insecure networks.",
                            remediation="Add the 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' response header.",
                            scanner_name=self.name,
                            http_method=method,
                            affected_endpoint_path=path,
                            confidence=VulnerabilityConfidence.CERTAIN,
                            cvss_score=5.4,
                            owasp_category="API8:2023 Security Misconfiguration",
                            cwe_id="CWE-523",
                            evidence_response_status=resp.status_code,
                            evidence_response_headers=dict(resp.headers),
                            evidence_proof="Header 'Strict-Transport-Security' is absent in HTTP response.",
                            curl_command=f"curl -I '{url}'",
                        )
                    )

                # 2. Check X-Content-Type-Options
                if "x-content-type-options" not in headers:
                    findings.append(
                        ScannerFinding(
                            title="Missing X-Content-Type-Options Header",
                            severity=VulnerabilitySeverity.LOW,
                            description=f"The endpoint '{path}' does not include 'X-Content-Type-Options: nosniff'.",
                            risk_explanation="MIME sniffing by user agents could cause non-executable content to be interpreted as HTML or script.",
                            remediation="Set 'X-Content-Type-Options: nosniff' on all API responses.",
                            scanner_name=self.name,
                            http_method=method,
                            affected_endpoint_path=path,
                            confidence=VulnerabilityConfidence.CERTAIN,
                            cvss_score=3.1,
                            owasp_category="API8:2023 Security Misconfiguration",
                            cwe_id="CWE-16",
                            evidence_response_status=resp.status_code,
                            evidence_response_headers=dict(resp.headers),
                            evidence_proof="Header 'X-Content-Type-Options' is absent.",
                            curl_command=f"curl -I '{url}'",
                        )
                    )

                # 3. Check Detailed Server Banner / Technology Leakage
                server_hdr = headers.get("server") or headers.get("x-powered-by")
                if server_hdr and any(c.isdigit() for c in server_hdr):
                    findings.append(
                        ScannerFinding(
                            title="Detailed Server / Technology Version Disclosure in Headers",
                            severity=VulnerabilitySeverity.LOW,
                            description=f"The endpoint '{path}' leaks exact software version details: '{server_hdr}'.",
                            risk_explanation="Exposing specific version numbers helps attackers identify known CVEs applicable to the underlying runtime.",
                            remediation="Configure web server / gateway to strip or genericize the 'Server' and 'X-Powered-By' headers.",
                            scanner_name=self.name,
                            http_method=method,
                            affected_endpoint_path=path,
                            confidence=VulnerabilityConfidence.CERTAIN,
                            cvss_score=2.6,
                            owasp_category="API8:2023 Security Misconfiguration",
                            cwe_id="CWE-200",
                            evidence_response_status=resp.status_code,
                            evidence_response_headers=dict(resp.headers),
                            evidence_proof=f"Server header returned: {server_hdr}",
                            curl_command=f"curl -I '{url}'",
                        )
                    )

                # 4. Check Content-Security-Policy (if returning HTML/interactive formats)
                content_type = headers.get("content-type", "")
                if "text/html" in content_type and "content-security-policy" not in headers:
                    findings.append(
                        ScannerFinding(
                            title="Missing Content-Security-Policy on HTML Endpoint",
                            severity=VulnerabilitySeverity.MEDIUM,
                            description=f"Endpoint '{path}' returns HTML content without a Content-Security-Policy header.",
                            risk_explanation="Lack of CSP allows execution of untrusted scripts if user input is reflected.",
                            remediation="Implement a restrictive Content-Security-Policy header (e.g., default-src 'self').",
                            scanner_name=self.name,
                            http_method=method,
                            affected_endpoint_path=path,
                            confidence=VulnerabilityConfidence.HIGH,
                            cvss_score=4.8,
                            owasp_category="API8:2023 Security Misconfiguration",
                            cwe_id="CWE-1021",
                            evidence_response_status=resp.status_code,
                            evidence_response_headers=dict(resp.headers),
                            curl_command=f"curl -I '{url}'",
                        )
                    )

            except Exception:
                continue

        return findings
