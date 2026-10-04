from typing import Dict, Any, List, Optional
import httpx
from app.scanners.base import BaseScanner, ScannerFinding
from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence


class AuthorizationScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "AuthorizationScanner"

    @property
    def description(self) -> str:
        return "Tests for Broken Object-Level Authorization (BOLA/IDOR) indicators across parameterized resource endpoints using safe read-only identifier enumeration."

    @property
    def category(self) -> str:
        return "Object-Level Authorization"

    async def scan(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        credentials: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ScannerFinding]:
        findings = []

        # Find endpoints with path parameters like {id}, {userId}, {orderId}
        parameterized = [ep for ep in endpoints if "{" in ep.get("path", "") and ep.get("method") == "GET"]

        for ep in parameterized:
            path = ep.get("path", "")
            method = ep.get("method", "GET")

            # Check if substituting different identifiers (1 vs 2) returns data without user authorization checks
            url_1 = f"{base_url.rstrip('/')}/{path.lstrip('/')}".replace("{id}", "1").replace("{userId}", "1").replace("{order_id}", "101")
            url_2 = f"{base_url.rstrip('/')}/{path.lstrip('/')}".replace("{id}", "2").replace("{userId}", "2").replace("{order_id}", "102")

            try:
                resp_1 = await client.request(method, url_1, timeout=5.0)
                resp_2 = await client.request(method, url_2, timeout=5.0)

                # If both sequential IDs return 200 OK without specific tenancy/ownership token verification
                if resp_1.status_code == 200 and resp_2.status_code == 200 and resp_1.text != resp_2.text:
                    findings.append(
                        ScannerFinding(
                            title=f"Potential Broken Object-Level Authorization (BOLA / IDOR) on {path}",
                            severity=VulnerabilitySeverity.HIGH,
                            description=f"Endpoint '{path}' returns discrete object records when iterating path IDs ({url_1} vs {url_2}) without apparent tenant isolation checks.",
                            risk_explanation="Attackers can enumerate object IDs to access private data belonging to other users.",
                            remediation="Implement server-side object-level access control checks that verify whether the authenticated subject possesses authorization to access the specific requested object ID.",
                            scanner_name=self.name,
                            http_method=method,
                            affected_endpoint_path=path,
                            confidence=VulnerabilityConfidence.MEDIUM,
                            cvss_score=7.7,
                            owasp_category="API1:2023 Broken Object Level Authorization",
                            cwe_id="CWE-639",
                            nist_control="AC-3 Access Enforcement",
                            evidence_response_status=resp_1.status_code,
                            evidence_proof=f"Sequential ID probes to '{url_1}' and '{url_2}' both returned HTTP 200 with distinct object payloads.",
                            curl_command=f"curl '{url_1}' && curl '{url_2}'",
                        )
                    )
            except Exception:
                continue

        return findings
