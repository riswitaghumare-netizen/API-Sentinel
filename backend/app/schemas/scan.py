from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel
from app.models.scan import ScanStatus, ScanProfileType
from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence, VulnerabilityStatus


class ScanTriggerRequest(BaseModel):
    profile_type: ScanProfileType = ScanProfileType.STANDARD
    custom_scanners: Optional[List[str]] = None


class FindingEvidenceResponse(BaseModel):
    id: str
    request_headers: Dict[str, Any]
    request_body: Optional[str]
    response_status: Optional[int]
    response_headers: Dict[str, Any]
    response_body_snippet: Optional[str]
    redacted_proof: Optional[str]
    curl_command: Optional[str]


class FindingCommentCreate(BaseModel):
    comment_text: str


class FindingCommentResponse(BaseModel):
    id: str
    user_id: str
    user_name: Optional[str] = "Security Analyst"
    comment_text: str
    created_at: datetime


class FindingUpdateRequest(BaseModel):
    status: Optional[VulnerabilityStatus] = None
    assignee_id: Optional[str] = None
    due_date: Optional[datetime] = None


class ScanFindingResponse(BaseModel):
    id: str
    scan_id: str
    api_id: str
    api_name: Optional[str] = None
    endpoint_id: Optional[str]
    title: str
    severity: VulnerabilitySeverity
    cvss_score: float
    risk_score: float
    confidence: VulnerabilityConfidence
    http_method: str
    affected_endpoint_path: str
    parameter_name: Optional[str]
    description: str
    risk_explanation: str
    remediation: str
    references: List[str]
    owasp_category: Optional[str]
    cwe_id: Optional[str]
    nist_control: Optional[str]
    status: VulnerabilityStatus
    scanner_name: str
    assignee_id: Optional[str]
    assignee_name: Optional[str] = None
    due_date: Optional[datetime]
    first_detected_at: datetime
    last_detected_at: datetime
    created_at: datetime
    evidence: Optional[FindingEvidenceResponse] = None
    comments: List[FindingCommentResponse] = []


class ScanResponse(BaseModel):
    id: str
    api_id: str
    api_name: Optional[str] = None
    profile_type: ScanProfileType
    profile_name: str
    status: ScanStatus
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    duration_seconds: float
    total_requests: int
    endpoints_tested: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    scanner_modules_executed: List[str]
    error_message: Optional[str]
    created_at: datetime
    findings: List[ScanFindingResponse] = []
