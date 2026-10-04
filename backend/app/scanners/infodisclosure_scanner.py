import re
from typing import Dict, Any, List, Optional
import httpx
from app.scanners.base import BaseScanner, ScannerFinding
from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence

# Patterns indicative of stack traces, internal paths, and debug information
STACK_TRACE_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\):", re.I), "Python Exception Traceback"),
    (re.compile(r"at ([\w\.\$]+)\(([\w]+\.java:\d+)\)", re.I), "Java Exception Stack Trace"),
    (re.compile(r"at ([\w\.\/]+)\:(\d+)\:(\d+)", re.I), "Node.js / JavaScript Stack Trace"),
    (re.compile(r"System\.(NullReferenceException|Exception|Data)", re.I), ".NET CLR Stack Trace"),
    (re.compile(r"(SQLSTATE\[\w+\]|syntax error at or near|ORA-\d{5}|mysql_fetch_array)", re.I), "Database Query Error Details"),
    (re.compile(r"(\/var\/www\/|\/home\/[\w\-]+\/|C:\\\\inetpub\\\\|C:\\\\Users\\\\)", re.I), "Internal Server File Path Disclosure"),
]


class InfoDisclosureScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "InformationDisclosureScanner"

    @property
    def description(self) -> str:
        return "Detects stack traces, unhandled internal exceptions, framework debug banners, and path leakage in API responses."

    @property
    def category(self) -> str:
        return "Information Disclosure & Error Handling"

    async def scan(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        credentials: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ScannerFinding]:
        findings = []
        target_endpoints = endpoints[:6] if endpoints else [{"path": "/", "method": "GET"}]

        # Test probes that trigger common edge cases safely
        probes = [
            ("Malformed Parameter", {"param": "'\"\\/<>%27%22"}),
            ("Type Mismatch", {"id": "invalid_string_where_number_expected"}),
            ("Nonexistent Resource", "/nonexistent-resource-sentinel-test-404"),
        ]

        for ep in target_endpoints:
            path = ep.get("path", "/")
            method = ep.get("method", "GET")
            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

            # 1. Inspect normal response first
            try:
                resp = await client.request(method, url, timeout=5.0)
                self._check_body_and_headers(resp, path, method, url, findings, "Normal Request")
            except Exception:
                pass

            # 2. Inspect error response by probing with non-existent path or parameter
            try:
                error_url = f"{url}?debug=1&id=null&test_param={probes[0][1]['param']}"
                resp_err = await client.request(method, error_url, timeout=5.0)
                self._check_body_and_headers(resp_err, path, method, error_url, findings, "Edge-Case Probe")
            except Exception:
                pass

        # 3. Dedicated 404 test on base URL
        try:
            not_found_url = f"{base_url.rstrip('/')}/sentinel_probe_debug_404_check"
            resp_404 = await client.get(not_found_url, timeout=5.0)
            self._check_body_and_headers(resp_404, "/sentinel_probe_debug_404_check", "GET", not_found_url, findings, "404 Handler")
        except Exception:
            pass

        return findings

    def _check_body_and_headers(
        self,
        resp: httpx.Response,
        path: str,
        method: str,
        url: str,
        findings: List[ScannerFinding],
        context_label: str,
    ):
        body_text = resp.text or ""
        
        # Check debug headers
        for h_key, h_val in resp.headers.items():
            if h_key.lower().startswith("x-debug") or h_key.lower() in ("x-runtime", "x-aspnet-version"):
                findings.append(
                    ScannerFinding(
                        title=f"Debug / Framework Diagnostic Header Disclosed ({h_key})",
                        severity=VulnerabilitySeverity.LOW,
                        description=f"Endpoint '{path}' returned debug/diagnostic header: '{h_key}: {h_val}'.",
                        risk_explanation="Exposing internal diagnostic headers aids attackers during reconnaissance.",
                        remediation="Disable debug mode and remove custom diagnostic response headers in production environments.",
                        scanner_name=self.name,
                        http_method=method,
                        affected_endpoint_path=path,
                        confidence=VulnerabilityConfidence.CERTAIN,
                        cvss_score=3.2,
                        owasp_category="API8:2023 Security Misconfiguration",
                        cwe_id="CWE-200",
                        evidence_response_status=resp.status_code,
                        evidence_response_headers=dict(resp.headers),
                        evidence_proof=f"Header '{h_key}' = '{h_val}'",
                        curl_command=f"curl -I '{url}'",
                    )
                )

        # Check stack traces in response body
        for pattern, pattern_name in STACK_TRACE_PATTERNS:
            match = pattern.search(body_text)
            if match:
                snippet = body_text[max(0, match.start() - 50) : min(len(body_text), match.end() + 200)]
                findings.append(
                    ScannerFinding(
                        title=f"Verbose Error / Stack Trace Disclosure ({pattern_name})",
                        severity=VulnerabilitySeverity.HIGH if "Database" in pattern_name or "Traceback" in pattern_name else VulnerabilitySeverity.MEDIUM,
                        description=f"Endpoint '{path}' leaked detailed internal runtime exception details during {context_label}.",
                        risk_explanation="Stack traces expose underlying source code filenames, line numbers, database schema names, and internal logic to untrusted clients.",
                        remediation="Implement global exception handling middleware to catch unhandled errors and return generic, sanitized JSON error responses without stack traces.",
                        scanner_name=self.name,
                        http_method=method,
                        affected_endpoint_path=path,
                        confidence=VulnerabilityConfidence.CERTAIN,
                        cvss_score=7.1 if "Database" in pattern_name else 6.3,
                        owasp_category="API8:2023 Security Misconfiguration",
                        cwe_id="CWE-209",
                        nist_control="SI-11 Error Handling",
                        evidence_response_status=resp.status_code,
                        evidence_response_body=body_text[:1000],
                        evidence_proof=f"Matched pattern '{pattern_name}': {snippet.strip()}",
                        curl_command=f"curl '{url}'",
                    )
                )
                break  # avoid multiple duplicates for same endpoint
