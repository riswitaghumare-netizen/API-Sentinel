from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, HttpUrl
from app.models.api import APIEnvironment, RiskClassification, MonitoringStatus, HealthStatus, AuthType


class APICredentialCreate(BaseModel):
    auth_type: AuthType
    key_name: str = "default"
    header_name: Optional[str] = "Authorization"
    secret_value: str  # Plaintext from user during create, encrypted immediately at rest


class APICredentialResponse(BaseModel):
    id: str
    auth_type: AuthType
    key_name: str
    header_name: Optional[str]
    masked_preview: str
    created_at: datetime


class APIEndpointCreate(BaseModel):
    path: str
    method: str = "GET"
    summary: Optional[str] = None
    description: Optional[str] = None
    parameters: Optional[List[Dict[str, Any]]] = []
    request_body_schema: Optional[Dict[str, Any]] = {}
    responses_schema: Optional[Dict[str, Any]] = {}
    is_authenticated: bool = False
    auth_type: AuthType = AuthType.NONE
    is_deprecated: bool = False
    tags: Optional[List[str]] = []


class APIEndpointResponse(BaseModel):
    id: str
    path: str
    method: str
    summary: Optional[str]
    description: Optional[str]
    parameters: List[Dict[str, Any]]
    request_body_schema: Dict[str, Any]
    responses_schema: Dict[str, Any]
    is_authenticated: bool
    auth_type: AuthType
    is_deprecated: bool
    tags: List[str]
    last_tested_at: Optional[datetime]


class APICreate(BaseModel):
    project_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    base_url: str
    environment: APIEnvironment = APIEnvironment.DEVELOPMENT
    owner: Optional[str] = None
    team: Optional[str] = None
    tags: Optional[List[str]] = []
    technology: Optional[str] = "FastAPI / REST"
    version: str = "v1.0.0"
    risk_classification: RiskClassification = RiskClassification.MEDIUM
    monitoring_status: MonitoringStatus = MonitoringStatus.ENABLED
    credentials: Optional[List[APICredentialCreate]] = None


class APIUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    base_url: Optional[str] = None
    environment: Optional[APIEnvironment] = None
    owner: Optional[str] = None
    team: Optional[str] = None
    tags: Optional[List[str]] = None
    technology: Optional[str] = None
    version: Optional[str] = None
    risk_classification: Optional[RiskClassification] = None
    monitoring_status: Optional[MonitoringStatus] = None


class OpenAPIImportRequest(BaseModel):
    spec_content: str  # JSON or YAML string
    base_url_override: Optional[str] = None


class APIListItemResponse(BaseModel):
    id: str
    project_id: str
    name: str
    description: Optional[str]
    base_url: str
    environment: APIEnvironment
    owner: Optional[str]
    team: Optional[str]
    tags: List[str]
    technology: Optional[str]
    version: str
    monitoring_status: MonitoringStatus
    risk_classification: RiskClassification
    security_score: float
    health_status: HealthStatus
    endpoints_count: int = 0
    open_vulnerabilities_count: int = 0
    last_scanned_at: Optional[datetime]
    last_monitored_at: Optional[datetime]
    created_at: datetime


class APIDetailResponse(APIListItemResponse):
    endpoints: List[APIEndpointResponse] = []
    credentials: List[APICredentialResponse] = []
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    info_vulns: int = 0
