from typing import Dict, Any, List
from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence
from app.models.api import APIEnvironment, RiskClassification


# Severity baseline numerical mapping
SEVERITY_WEIGHTS = {
    VulnerabilitySeverity.CRITICAL: 9.5,
    VulnerabilitySeverity.HIGH: 7.5,
    VulnerabilitySeverity.MEDIUM: 5.0,
    VulnerabilitySeverity.LOW: 2.5,
    VulnerabilitySeverity.INFORMATIONAL: 0.5,
}

CONFIDENCE_MULTIPLIER = {
    VulnerabilityConfidence.CERTAIN: 1.0,
    VulnerabilityConfidence.HIGH: 0.9,
    VulnerabilityConfidence.MEDIUM: 0.75,
    VulnerabilityConfidence.LOW: 0.5,
}

ENV_MULTIPLIER = {
    APIEnvironment.PRODUCTION: 1.2,
    APIEnvironment.STAGING: 1.0,
    APIEnvironment.TESTING: 0.8,
    APIEnvironment.DEVELOPMENT: 0.7,
}


def calculate_finding_risk_score(
    severity: VulnerabilitySeverity,
    confidence: VulnerabilityConfidence = VulnerabilityConfidence.HIGH,
    environment: APIEnvironment = APIEnvironment.DEVELOPMENT,
    risk_classification: RiskClassification = RiskClassification.MEDIUM,
) -> float:
    """
    Calculates a multi-factor risk score (0.0 to 10.0) based on severity, 
    detection confidence, target environment exposure, and business criticality.
    """
    base_severity = SEVERITY_WEIGHTS.get(severity, 5.0)
    conf_mult = CONFIDENCE_MULTIPLIER.get(confidence, 0.9)
    env_mult = ENV_MULTIPLIER.get(environment, 1.0)
    
    # Business criticality adjustment
    crit_adj = 0.0
    if risk_classification == RiskClassification.CRITICAL:
        crit_adj = 0.8
    elif risk_classification == RiskClassification.HIGH:
        crit_adj = 0.4
    elif risk_classification == RiskClassification.LOW:
        crit_adj = -0.4

    raw_score = (base_severity * conf_mult * env_mult) + crit_adj
    # Clamp score between 0.1 and 10.0
    final_score = max(0.1, min(10.0, raw_score))
    return round(final_score, 1)


def calculate_api_security_score(
    findings: List[Dict[str, Any]],
    has_tls: bool = True,
    has_headers: bool = True,
    has_auth_covered: bool = True,
    has_rate_limiting: bool = True,
    has_spec_accurate: bool = True,
    is_monitored: bool = True,
) -> float:
    """
    Calculates an API Security Score (0 to 100).
    Factors:
    - Base: 100.0
    - Vulnerability deductions (Critical -25 each, High -12 each, Med -5 each, Low -2 each)
    - Security posture bonuses / penalties:
      * TLS active: 10 pts
      * Security headers complete: 10 pts
      * Auth configured: 20 pts
      * Rate limiting verified: 10 pts
      * OpenAPI spec synced: 10 pts
      * Active monitoring: 5 pts
    """
    score = 100.0

    # Deduct for findings
    for finding in findings:
        sev = finding.get("severity")
        status = finding.get("status")
        # Ignore false positives or remediated
        if status in ("FALSE_POSITIVE", "REMEDIATED", "ACCEPTED_RISK"):
            continue
            
        if sev in (VulnerabilitySeverity.CRITICAL, "CRITICAL"):
            score -= 25.0
        elif sev in (VulnerabilitySeverity.HIGH, "HIGH"):
            score -= 12.0
        elif sev in (VulnerabilitySeverity.MEDIUM, "MEDIUM"):
            score -= 5.0
        elif sev in (VulnerabilitySeverity.LOW, "LOW"):
            score -= 2.0
        elif sev in (VulnerabilitySeverity.INFORMATIONAL, "INFORMATIONAL"):
            score -= 0.5

    # Posture adjustments
    if not has_tls:
        score -= 10.0
    if not has_headers:
        score -= 8.0
    if not has_auth_covered:
        score -= 15.0
    if not has_rate_limiting:
        score -= 7.0
    if not has_spec_accurate:
        score -= 5.0
    if not is_monitored:
        score -= 5.0

    return max(0.0, min(100.0, round(score, 1)))


def get_security_score_grade(score: float) -> str:
    """Returns the descriptive grade corresponding to a security score."""
    if score >= 95.0:
        return "Excellent"
    elif score >= 80.0:
        return "Good"
    elif score >= 60.0:
        return "Needs Improvement"
    elif score >= 40.0:
        return "Poor"
    else:
        return "Critical"
