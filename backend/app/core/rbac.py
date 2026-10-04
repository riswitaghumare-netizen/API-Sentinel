from enum import Enum
from typing import List, Set


class Role(str, Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"


class Permission(str, Enum):
    # User & Org Management
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    ORG_MANAGE = "org:manage"

    # API Management
    API_CREATE = "api:create"
    API_READ = "api:read"
    API_UPDATE = "api:update"
    API_DELETE = "api:delete"
    API_CREDENTIALS = "api:credentials"

    # Scans
    SCAN_START = "scan:start"
    SCAN_READ = "scan:read"
    SCAN_CANCEL = "scan:cancel"
    SCAN_CONFIGURE = "scan:configure"

    # Vulnerabilities
    VULN_READ = "vuln:read"
    VULN_UPDATE = "vuln:update"
    VULN_ASSIGN = "vuln:assign"
    VULN_COMMENT = "vuln:comment"

    # Monitoring & Alerts
    MONITORING_READ = "monitoring:read"
    MONITORING_MANAGE = "monitoring:manage"
    ALERT_READ = "alert:read"
    ALERT_MANAGE = "alert:manage"

    # Reports & Audit
    REPORT_GENERATE = "report:generate"
    REPORT_READ = "report:read"
    AUDIT_READ = "audit:read"


ROLE_PERMISSIONS: dict[Role, Set[Permission]] = {
    Role.SUPER_ADMIN: set(Permission),  # All permissions
    Role.SECURITY_ADMIN: {
        Permission.USER_READ,
        Permission.API_CREATE,
        Permission.API_READ,
        Permission.API_UPDATE,
        Permission.API_DELETE,
        Permission.API_CREDENTIALS,
        Permission.SCAN_START,
        Permission.SCAN_READ,
        Permission.SCAN_CANCEL,
        Permission.SCAN_CONFIGURE,
        Permission.VULN_READ,
        Permission.VULN_UPDATE,
        Permission.VULN_ASSIGN,
        Permission.VULN_COMMENT,
        Permission.MONITORING_READ,
        Permission.MONITORING_MANAGE,
        Permission.ALERT_READ,
        Permission.ALERT_MANAGE,
        Permission.REPORT_GENERATE,
        Permission.REPORT_READ,
        Permission.AUDIT_READ,
    },
    Role.SECURITY_ANALYST: {
        Permission.API_READ,
        Permission.SCAN_START,
        Permission.SCAN_READ,
        Permission.VULN_READ,
        Permission.VULN_UPDATE,
        Permission.VULN_ASSIGN,
        Permission.VULN_COMMENT,
        Permission.MONITORING_READ,
        Permission.ALERT_READ,
        Permission.ALERT_MANAGE,
        Permission.REPORT_GENERATE,
        Permission.REPORT_READ,
        Permission.AUDIT_READ,
    },
    Role.DEVELOPER: {
        Permission.API_READ,
        Permission.SCAN_START,
        Permission.SCAN_READ,
        Permission.VULN_READ,
        Permission.VULN_COMMENT,
        Permission.MONITORING_READ,
        Permission.ALERT_READ,
        Permission.REPORT_READ,
    },
    Role.VIEWER: {
        Permission.API_READ,
        Permission.SCAN_READ,
        Permission.VULN_READ,
        Permission.MONITORING_READ,
        Permission.ALERT_READ,
        Permission.REPORT_READ,
    },
}


def has_permission(role: Role, permission: Permission) -> bool:
    """Checks if a given role possesses a specific permission."""
    perms = ROLE_PERMISSIONS.get(role, set())
    return permission in perms
