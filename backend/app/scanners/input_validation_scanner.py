from typing import Dict, Any, List, Optional
import httpx
from app.scanners.base import BaseScanner, ScannerFinding
from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence


class InputValidationScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "InputValidationScanner"

    @property
    def description(self) -> str:
        return "Sends non-destructive type confusion and boundary test payloads to verify whether API endpoints enforce schema validation rather than throwing unhandled 500 errors."

    @property
    def category(self) -> str:
        return "Input Validation & Data Integrity"

    async def scan(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        credentials: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ScannerFinding]:
        findings = []
        target_endpoints = endpoints[:6] if endpoints else []

        for ep in target_endpoints:
            path = ep.get("path", "/")
            method = ep.get("method", "GET")
            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            test_url = url.replace("{id}", "999999999999999999999999999999999999999999999")

            # 1. Test unhandled numeric overflow / string type mismatch in path
            try:
                resp = await client.request(method, test_url, timeout=5.0)
                # If API crashes with 500 Internal Server Error instead of 400/404/422
                if resp.status_code == 500:
                    findings.append(
                        ScannerFinding(
                            title=f"Unhandled Server Exception on Malformed Input ({path})",
                            severity=VulnerabilitySeverity.MEDIUM,
                            description=f"Endpoint '{path}' crashed with HTTP 500 Internal Server Error when receiving boundary input.",
                            risk_explanation="Unhandled exceptions indicate missing input validation layers and may expose denial-of-service or edge-case exploitation vectors.",
                            remediation="Validate parameter types and ranges before processing, and return clean 422 Unprocessable Entity or 400 Bad Request responses.",
                            scanner_name=self.name,
                            http_method=method,
                            affected_endpoint_path=path,
                            confidence=VulnerabilityConfidence.HIGH,
                            cvss_score=5.0,
                            owasp_category="API8:2023 Security Misconfiguration",
                            cwe_id="CWE-20",
                            evidence_response_status=resp.status_code,
                            evidence_response_body=resp.text[:400] if resp.text else None,
                            curl_command=f"curl -X {method} '{test_url}'",
                        )
                    )
            except Exception:
                pass

            # 2. If POST/PUT, test empty JSON body or unexpected type in JSON body
            if method in ("POST", "PUT", "PATCH"):
                try:
                    resp_body_test = await client.request(
                        method,
                        url,
                        json={"invalid_field_sentinel": [None, 12345, {"nested": True}]},
                        timeout=5.0,
                    )
                    if resp_body_test.status_code == 500:
                        findings.append(
                            ScannerFinding(
                                title=f"Missing Request Body Schema Validation ({path})",
                                severity=VulnerabilitySeverity.MEDIUM,
                                description=f"Endpoint '{path}' responded with HTTP 500 when presented with unexpected request body JSON fields.",
                                risk_explanation="The application failed to reject unrecognized schema attributes gracefully.",
                                remediation="Enforce strict request body schema validation using Pydantic, Zod, or JSON Schema validation middleware.",
                                scanner_name=self.name,
                                http_method=method,
                                affected_endpoint_path=path,
                                confidence=VulnerabilityConfidence.HIGH,
                                cvss_score=5.2,
                                owasp_category="API8:2023 Security Misconfiguration",
                                cwe_id="CWE-20",
                                evidence_response_status=resp_body_test.status_code,
                                curl_command=f"curl -X {method} -H 'Content-Type: application/json' -d '{{\"invalid_field\": 1}}' '{url}'",
                            )
                        )
                except Exception:
                    pass

        return findings
