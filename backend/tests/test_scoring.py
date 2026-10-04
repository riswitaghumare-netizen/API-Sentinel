from app.models.vulnerability import VulnerabilitySeverity, VulnerabilityConfidence
from app.models.api import APIEnvironment, RiskClassification
from app.services.scoring_service import (
    calculate_finding_risk_score,
    calculate_api_security_score,
    get_security_score_grade,
)


def test_calculate_finding_risk_score():
    # Critical in Production with High Confidence
    score_prod = calculate_finding_risk_score(
        severity=VulnerabilitySeverity.CRITICAL,
        confidence=VulnerabilityConfidence.HIGH,
        environment=APIEnvironment.PRODUCTION,
        risk_classification=RiskClassification.CRITICAL,
    )
    assert score_prod >= 9.0

    # Low in Dev
    score_dev = calculate_finding_risk_score(
        severity=VulnerabilitySeverity.LOW,
        confidence=VulnerabilityConfidence.LOW,
        environment=APIEnvironment.DEVELOPMENT,
        risk_classification=RiskClassification.LOW,
    )
    assert score_dev < 3.0


def test_calculate_api_security_score():
    # Clean API
    perfect_score = calculate_api_security_score(findings=[])
    assert perfect_score == 100.0
    assert get_security_score_grade(perfect_score) == "Excellent"

    # API with Critical finding
    findings = [{"severity": VulnerabilitySeverity.CRITICAL, "status": "OPEN"}]
    crit_score = calculate_api_security_score(findings=findings)
    assert crit_score <= 75.0
