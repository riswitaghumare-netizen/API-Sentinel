from typing import Dict, List, Type
from app.scanners.base import BaseScanner
from app.scanners.header_scanner import HeaderScanner
from app.scanners.cors_scanner import CORScanner
from app.scanners.tls_scanner import TLSScanner
from app.scanners.ratelimit_scanner import RateLimitScanner
from app.scanners.infodisclosure_scanner import InfoDisclosureScanner
from app.scanners.openapi_scanner import OpenAPIScanner
from app.scanners.auth_scanner import AuthenticationScanner
from app.scanners.authz_scanner import AuthorizationScanner
from app.scanners.input_validation_scanner import InputValidationScanner
from app.scanners.security_policy_scanner import SecurityPolicyScanner
from app.models.scan import ScanProfileType


ALL_SCANNERS: Dict[str, BaseScanner] = {
    "HeaderScanner": HeaderScanner(),
    "CORScanner": CORScanner(),
    "TLSScanner": TLSScanner(),
    "RateLimitScanner": RateLimitScanner(),
    "InformationDisclosureScanner": InfoDisclosureScanner(),
    "OpenAPIScanner": OpenAPIScanner(),
    "AuthenticationScanner": AuthenticationScanner(),
    "AuthorizationScanner": AuthorizationScanner(),
    "InputValidationScanner": InputValidationScanner(),
    "SecurityPolicyScanner": SecurityPolicyScanner(),
}


def get_scanners_for_profile(
    profile_type: ScanProfileType,
    custom_scanners: List[str] = None,
) -> List[BaseScanner]:
    """Returns the list of scanner instances configured for a given scan profile."""
    if profile_type == ScanProfileType.QUICK:
        names = ["HeaderScanner", "TLSScanner", "CORScanner", "InformationDisclosureScanner"]
    elif profile_type == ScanProfileType.STANDARD:
        names = [
            "HeaderScanner",
            "CORScanner",
            "TLSScanner",
            "RateLimitScanner",
            "InformationDisclosureScanner",
            "OpenAPIScanner",
            "AuthenticationScanner",
            "SecurityPolicyScanner",
        ]
    elif profile_type == ScanProfileType.DEEP:
        names = list(ALL_SCANNERS.keys())
    elif profile_type == ScanProfileType.CUSTOM and custom_scanners:
        names = [name for name in custom_scanners if name in ALL_SCANNERS]
    else:
        names = list(ALL_SCANNERS.keys())

    return [ALL_SCANNERS[name] for name in names if name in ALL_SCANNERS]
