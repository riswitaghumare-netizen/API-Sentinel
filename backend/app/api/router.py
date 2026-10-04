from fastapi import APIRouter
from app.api.v1 import (
    auth,
    organizations,
    apis,
    scans,
    vulnerabilities,
    monitoring,
    alerts,
    reports,
    audit_logs,
    dashboard,
)

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(organizations.router)
api_router.include_router(apis.router)
api_router.include_router(scans.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(monitoring.router)
api_router.include_router(alerts.router)
api_router.include_router(reports.router)
api_router.include_router(audit_logs.router)
api_router.include_router(dashboard.router)
