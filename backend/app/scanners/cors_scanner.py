from typing import Dict, Any, List, Optional
import httpx
from app.scanners.base import BaseScanner, ScannerFinding
from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence


class CORScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "CORScanner"

    @property
    def description(self) -> str:
        return "Tests Cross-Origin Resource Sharing (CORS) configurations for wildcard origins, origin reflection, and insecure credential allowances."

    @property
    def category(self) -> str:
        return "Cross-Origin Security"

    async def scan(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        credentials: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ScannerFinding]:
        findings = []
        target_endpoints = endpoints[:4] if endpoints else [{"path": "/", "method": "GET"}]
        test_origins = ["https://evil-attacker.example.com", "null"]

        for ep in target_endpoints:
            path = ep.get("path", "/")
            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

            for origin in test_origins:
                headers = {
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "Authorization,Content-Type",
                }

                try:
                    # Test preflight OPTIONS request
                    resp_options = await client.request("OPTIONS", url, headers=headers, timeout=5.0)
                    resp_get = await client.request("GET", url, headers={"Origin": origin}, timeout=5.0)

                    for resp, probe_method in [(resp_options, "OPTIONS"), (resp_get, "GET")]:
                        acao = resp.headers.get("access-control-allow-origin")
                        acac = resp.headers.get("access-control-allow-credentials", "").lower()

                        if acao:
                            # 1. Critical: Credentialed wildcard or reflected origin with credentials
                            if acac == "true" and (acao == "*" or acao == origin):
                                findings.append(
                                    ScannerFinding(
                                        title="Insecure Credentialed CORS Configuration (Arbitrary Origin Allowed)",
                                        severity=VulnerabilitySeverity.HIGH,
                                        description=f"Endpoint '{path}' reflects arbitrary Origin '{origin}' with 'Access-Control-Allow-Credentials: true'.",
                                        risk_explanation="Malicious websites can issue authenticated cross-origin XMLHttpRequests/fetch to read private user responses.",
                                        remediation="Do not dynamically mirror arbitrary Origin headers when credentials (cookies/auth headers) are allowed. Maintain a strict server-side whitelist.",
                                        scanner_name=self.name,
                                        http_method=probe_method,
                                        affected_endpoint_path=path,
                                        confidence=VulnerabilityConfidence.CERTAIN,
                                        cvss_score=7.8,
                                        owasp_category="API8:2023 Security Misconfiguration",
                                        cwe_id="CWE-942",
                                        evidence_request_headers=headers,
                                        evidence_response_status=resp.status_code,
                                        evidence_response_headers=dict(resp.headers),
                                        evidence_proof=f"Response headers contain: Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                                        curl_command=f"curl -X {probe_method} -H 'Origin: {origin}' -I '{url}'",
                                    )
                                )
                                break  # Break origin loop for this endpoint

                            # 2. Medium: Overly permissive wildcard origin on API endpoint
                            elif acao == "*" and probe_method == "GET":
                                findings.append(
                                    ScannerFinding(
                                        title="Overly Permissive CORS Policy (Wildcard Origin '*')",
                                        severity=VulnerabilitySeverity.LOW,
                                        description=f"Endpoint '{path}' returns 'Access-Control-Allow-Origin: *'.",
                                        risk_explanation="Allows any website to read unauthenticated responses from this API endpoint.",
                                        remediation="If the API is private or contains internal data, restrict the allowed origins to authorized client domains.",
                                        scanner_name=self.name,
                                        http_method=probe_method,
                                        affected_endpoint_path=path,
                                        confidence=VulnerabilityConfidence.HIGH,
                                        cvss_score=3.7,
                                        owasp_category="API8:2023 Security Misconfiguration",
                                        cwe_id="CWE-942",
                                        evidence_request_headers={"Origin": origin},
                                        evidence_response_status=resp.status_code,
                                        evidence_response_headers=dict(resp.headers),
                                        evidence_proof=f"Access-Control-Allow-Origin: {acao}",
                                        curl_command=f"curl -H 'Origin: {origin}' -I '{url}'",
                                    )
                                )
                                break
                except Exception:
                    continue

        return findings
