from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import httpx
from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence
from app.core.encryption import redact_evidence


class ScannerFinding:
    def __init__(
        self,
        title: str,
        severity: VulnerabilitySeverity,
        description: str,
        risk_explanation: str,
        remediation: str,
        scanner_name: str,
        http_method: str = "GET",
        affected_endpoint_path: str = "/",
        parameter_name: Optional[str] = None,
        confidence: VulnerabilityConfidence = VulnerabilityConfidence.HIGH,
        cvss_score: float = 5.0,
        owasp_category: Optional[str] = None,
        cwe_id: Optional[str] = None,
        nist_control: Optional[str] = None,
        references: Optional[List[str]] = None,
        evidence_request_headers: Optional[Dict[str, Any]] = None,
        evidence_request_body: Optional[str] = None,
        evidence_response_status: Optional[int] = None,
        evidence_response_headers: Optional[Dict[str, Any]] = None,
        evidence_response_body: Optional[str] = None,
        evidence_proof: Optional[str] = None,
        curl_command: Optional[str] = None,
    ):
        self.title = title
        self.severity = severity
        self.description = description
        self.risk_explanation = risk_explanation
        self.remediation = remediation
        self.scanner_name = scanner_name
        self.http_method = http_method
        self.affected_endpoint_path = affected_endpoint_path
        self.parameter_name = parameter_name
        self.confidence = confidence
        self.cvss_score = cvss_score
        self.owasp_category = owasp_category or "API Security Best Practice"
        self.cwe_id = cwe_id or "CWE-693"
        self.nist_control = nist_control or "SC-8 Transmission Confidentiality and Integrity"
        self.references = references or ["https://owasp.org/www-project-api-security/"]
        
        # Redacted evidence
        self.evidence_request_headers = evidence_request_headers or {}
        self.evidence_request_body = evidence_request_body
        self.evidence_response_status = evidence_response_status
        self.evidence_response_headers = evidence_response_headers or {}
        self.evidence_response_body = redact_evidence(evidence_response_body[:2000]) if evidence_response_body else None
        self.evidence_proof = redact_evidence(evidence_proof) if evidence_proof else None
        self.curl_command = redact_evidence(curl_command) if curl_command else None


class BaseScanner(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier of the scanner module."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this scanner assesses."""
        pass

    @property
    def category(self) -> str:
        return "General API Security"

    @abstractmethod
    async def scan(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        credentials: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[ScannerFinding]:
        """
        Executes safe, non-destructive defensive checks against authorized endpoints.
        """
        pass
