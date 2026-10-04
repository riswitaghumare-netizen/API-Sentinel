from typing import Dict, Any, List, Optional
import asyncio
import httpx
from app.scanners.base import BaseScanner, ScannerFinding
from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence


class RateLimitScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "RateLimitScanner"

    @property
    def description(self) -> str:
        return "Probes API endpoints with safe, controlled bursts to detect lack of rate limiting or missing rate-limit telemetry headers."

    @property
    def category(self) -> str:
        return "Resource Management & Rate Limiting"

    async def scan(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        credentials: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ScannerFinding]:
        findings = []
        target_ep = endpoints[0] if endpoints else {"path": "/", "method": "GET"}
        path = target_ep.get("path", "/")
        method = target_ep.get("method", "GET")
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

        # Safe controlled burst: 8 requests sent in rapid succession
        burst_count = 8
        responses = []

        try:
            for _ in range(burst_count):
                resp = await client.request(method, url, timeout=4.0)
                responses.append(resp)
                await asyncio.sleep(0.05)  # Slight delay to avoid overloading
        except Exception:
            return findings

        if not responses:
            return findings

        # Check for rate-limiting headers in the responses
        sample_resp = responses[0]
        headers = {k.lower(): v for k, v in sample_resp.headers.items()}
        has_ratelimit_header = any(
            h in headers for h in [
                "x-ratelimit-limit",
                "x-ratelimit-remaining",
                "ratelimit-limit",
                "ratelimit-remaining",
                "retry-after",
            ]
        )
        got_429 = any(r.status_code == 429 for r in responses)

        if not has_ratelimit_header and not got_429:
            findings.append(
                ScannerFinding(
                    title="Missing Rate Limiting & Throttling Controls",
                    severity=VulnerabilitySeverity.MEDIUM,
                    description=f"Endpoint '{path}' does not return standard rate-limiting headers (e.g. 'RateLimit-Limit', 'X-RateLimit-*') and accepted rapid successive requests without throttling.",
                    risk_explanation="Lack of rate limiting exposes the API to automated credential stuffing, denial-of-service, brute force, and uncontrolled resource consumption.",
                    remediation="Implement token-bucket or sliding-window rate limiting per IP or authenticated user (e.g. 100 requests/minute) and return 429 Too Many Requests with standard Retry-After headers.",
                    scanner_name=self.name,
                    http_method=method,
                    affected_endpoint_path=path,
                    confidence=VulnerabilityConfidence.HIGH,
                    cvss_score=5.3,
                    owasp_category="API4:2023 Unrestricted Resource Consumption",
                    cwe_id="CWE-770",
                    nist_control="SC-5 Denial of Service Protection",
                    evidence_response_status=sample_resp.status_code,
                    evidence_response_headers=dict(sample_resp.headers),
                    evidence_proof=f"Executed {burst_count} rapid sequential requests. All completed successfully without rate-limit headers or 429 status code.",
                    curl_command=f"for i in {{1..{burst_count}}}; do curl -s -o /dev/null -w '%{{http_code}}\\n' '{url}'; done",
                )
            )

        return findings
