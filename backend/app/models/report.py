import uuid
from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum as SQLEnum, Text, JSON
from app.core.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class ReportFormat(str, Enum):
    PDF = "PDF"
    HTML = "HTML"
    JSON = "JSON"
    CSV = "CSV"


class ReportScope(str, Enum):
    ALL_APIS = "ALL_APIS"
    PROJECT = "PROJECT"
    SINGLE_API = "SINGLE_API"


class SecurityReport(Base):
    __tablename__ = "security_reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    title = Column(String(255), nullable=False)
    scope = Column(SQLEnum(ReportScope), default=ReportScope.ALL_APIS, nullable=False)
    target_id = Column(String(36), nullable=True)  # API ID or Project ID
    
    generated_by_user_id = Column(String(36), nullable=True)
    report_format = Column(SQLEnum(ReportFormat), default=ReportFormat.HTML, nullable=False)
    
    summary_data = Column(JSON, default=dict, nullable=False)
    content_payload = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
