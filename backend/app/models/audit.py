import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    user_email = Column(String(255), nullable=True)
    
    action = Column(String(100), nullable=False)  # START_SCAN, CREATE_API, UPDATE_VULN, USER_LOGIN, etc.
    resource_type = Column(String(100), nullable=False)  # API, SCAN, FINDING, USER, ORG
    resource_id = Column(String(36), nullable=True)
    
    status = Column(String(50), default="SUCCESS", nullable=False)  # SUCCESS, FAILED, DENIED
    ip_address = Column(String(45), nullable=True)
    details = Column(JSON, default=dict, nullable=False)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)

    user = relationship("User", back_populates="audit_logs")
