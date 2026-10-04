from typing import Dict, Any, List, Optional
import httpx
from urllib.parse import urlparse
from app.scanners.base import BaseScanner, ScannerFinding
from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence


class TLSScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "TLSScanner"

    @property
    def description(self) -> str:
        return "Evaluates transport layer security, HTTPS enforcement, and plaintext HTTP downgrade behaviors."

    @property
    def category(self) -> str:
        return "Transport Security"

    async def scan(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        credentials: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ScannerFinding]:
        findings = []
        parsed = urlparse(base_url)

        # 1. Plaintext HTTP Check
        if parsed.scheme.lower() == "http":
            findings.append(
                ScannerFinding(
                    title="Insecure Plaintext HTTP Protocol in Use",
                    severity=VulnerabilitySeverity.HIGH,
                    description=f"The API Base URL is configured with plaintext HTTP: '{base_url}'.",
                    risk_explanation="API credentials, tokens, sensitive parameters, and response payloads are transmitted in cleartext, enabling eavesdropping and man-in-the-middle tampering.",
                    remediation="Migrate all API traffic to HTTPS using a valid TLS certificate and configure automatic HTTP-to-HTTPS 301 redirects.",
                    scanner_name=self.name,
                    http_method="ALL",
                    affected_endpoint_path=parsed.path or "/",
                    confidence=VulnerabilityConfidence.CERTAIN,
                    cvss_score=7.4,
                    owasp_category="API8:2023 Security Misconfiguration",
                    cwe_id="CWE-319",
                    evidence_proof=f"Base URL scheme is plaintext '{parsed.scheme}'.",
                    curl_command=f"curl -I '{base_url}'",
                )
            )

        # 2. Check HTTP to HTTPS redirect behavior if HTTPS is target
        if parsed.scheme.lower() == "https":
            http_url = f"http://{parsed.netloc}{parsed.path}"
            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=False) as http_client:
                    resp = await http_client.get(http_url, timeout=4.0)
                    if resp.status_code not in (301, 308):
                        findings.append(
                            ScannerFinding(
                                title="Insecure HTTP-to-HTTPS Redirection Behavior",
                                severity=VulnerabilitySeverity.MEDIUM,
                                description=f"HTTP endpoint '{http_url}' did not respond with a permanent redirect (301/308). Returned status: {resp.status_code}.",
                                risk_explanation="Clients inadvertently making plaintext requests may not be upgraded immediately to HTTPS.",
                                remediation="Ensure the web server / load balancer permanently redirects all HTTP requests to HTTPS.",
                                scanner_name=self.name,
                                http_method="GET",
                                affected_endpoint_path="/",
                                confidence=VulnerabilityConfidence.HIGH,
                                cvss_score=4.3,
                                owasp_category="API8:2023 Security Misconfiguration",
                                cwe_id="CWE-319",
                                evidence_response_status=resp.status_code,
                                curl_command=f"curl -I '{http_url}'",
                            )
                        )
            except Exception:
                pass

        return findings
