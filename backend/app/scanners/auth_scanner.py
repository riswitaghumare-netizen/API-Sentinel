from typing import Dict, Any, List, Optional
import httpx
from app.scanners.base import BaseScanner, ScannerFinding
from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence


class AuthenticationScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "AuthenticationScanner"

    @property
    def description(self) -> str:
        return "Checks whether sensitive or declared authenticated endpoints properly enforce authentication requirements when accessed without valid credentials."

    @property
    def category(self) -> str:
        return "Authentication & Access Controls"

    async def scan(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        credentials: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ScannerFinding]:
        findings = []

        sensitive_keywords = ["user", "account", "order", "payment", "admin", "secret", "profile", "setting", "invoice"]

        for ep in endpoints:
            path = ep.get("path", "/")
            method = ep.get("method", "GET")
            is_declared_auth = ep.get("is_authenticated", False)
            path_lower = path.lower()

            is_sensitive_path = any(kw in path_lower for kw in sensitive_keywords)

            # Test request without any Authorization header
            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            
            # Format path parameters safely if any (e.g. /users/{id} -> /users/1)
            test_url = url.replace("{id}", "1").replace("{user_id}", "1").replace("{order_id}", "101")

            try:
                # 1. Unauthenticated request probe
                resp_unauth = await client.request(method, test_url, timeout=5.0)

                # If declared as authenticated OR clearly sensitive path, but returns 200 OK without auth
                if resp_unauth.status_code == 200 and (is_declared_auth or (is_sensitive_path and "login" not in path_lower and "register" not in path_lower)):
                    findings.append(
                        ScannerFinding(
                            title=f"Missing Authentication on Sensitive API Endpoint ({path})",
                            severity=VulnerabilitySeverity.CRITICAL if "admin" in path_lower or "payment" in path_lower else VulnerabilitySeverity.HIGH,
                            description=f"Endpoint '{path}' returned HTTP 200 OK without requiring authentication headers or tokens.",
                            risk_explanation="Anonymous unauthenticated attackers can invoke this sensitive endpoint and access protected resources.",
                            remediation="Enforce server-side authentication middleware (e.g. JWT verification, OAuth2, or API Key check) on this route.",
                            scanner_name=self.name,
                            http_method=method,
                            affected_endpoint_path=path,
                            confidence=VulnerabilityConfidence.HIGH,
                            cvss_score=8.6 if "admin" in path_lower else 7.5,
                            owasp_category="API2:2023 Broken Authentication",
                            cwe_id="CWE-306",
                            nist_control="IA-2 Identification and Authentication",
                            evidence_response_status=resp_unauth.status_code,
                            evidence_response_body=resp_unauth.text[:400] if resp_unauth.text else None,
                            evidence_proof=f"Sent unauthenticated {method} request to '{test_url}'. Server returned status 200 OK.",
                            curl_command=f"curl -X {method} '{test_url}'",
                        )
                    )

                # 2. Test invalid/bogus token handling
                resp_invalid_token = await client.request(
                    method,
                    test_url,
                    headers={"Authorization": "Bearer sentinel_invalid_test_token_12345"},
                    timeout=5.0,
                )
                if resp_invalid_token.status_code == 200 and is_declared_auth:
                    findings.append(
                        ScannerFinding(
                            title=f"Authentication Bypass with Malformed/Forged Token ({path})",
                            severity=VulnerabilitySeverity.CRITICAL,
                            description=f"Endpoint '{path}' accepted a completely bogus Bearer token and returned HTTP 200 OK.",
                            risk_explanation="Indicates lack of cryptographic signature verification on JWTs or tokens.",
                            remediation="Validate signature, expiration, and issuer of all incoming bearer tokens using a robust authentication library.",
                            scanner_name=self.name,
                            http_method=method,
                            affected_endpoint_path=path,
                            confidence=VulnerabilityConfidence.CERTAIN,
                            cvss_score=9.8,
                            owasp_category="API2:2023 Broken Authentication",
                            cwe_id="CWE-287",
                            nist_control="IA-5 Authenticator Management",
                            evidence_response_status=resp_invalid_token.status_code,
                            evidence_proof="Sent invalid Bearer token. Server returned 200 OK instead of 401 Unauthorized.",
                            curl_command=f"curl -X {method} -H 'Authorization: Bearer invalid_token' '{test_url}'",
                        )
                    )

            except Exception:
                continue

        return findings
