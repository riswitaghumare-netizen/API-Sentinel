from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class SeverityDistribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0


class VulnerabilityTrendPoint(BaseModel):
    date: str
    critical: int
    high: int
    medium: int
    low: int


class TopRiskAPI(BaseModel):
    id: str
    name: str
    environment: str
    security_score: float
    critical_count: int
    high_count: int
    risk_level: str


class DashboardStatsResponse(BaseModel):
    total_apis: int = 0
    monitored_apis: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    open_findings: int = 0
    average_security_score: float = 100.0
    overall_availability: float = 100.0
    active_alerts: int = 0
    severity_distribution: SeverityDistribution
    vulnerability_trends: List[VulnerabilityTrendPoint] = []
    top_risks: List[TopRiskAPI] = []
    recent_scans: List[Dict[str, Any]] = []
