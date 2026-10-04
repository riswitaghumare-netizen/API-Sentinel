from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel
from app.models.report import ReportFormat, ReportScope


class ReportGenerateRequest(BaseModel):
    title: str
    scope: ReportScope = ReportScope.ALL_APIS
    target_id: Optional[str] = None
    report_format: ReportFormat = ReportFormat.HTML


class ReportResponse(BaseModel):
    id: str
    title: str
    scope: ReportScope
    target_id: Optional[str]
    report_format: ReportFormat
    summary_data: Dict[str, Any]
    content_payload: Optional[str] = None
    created_at: datetime
