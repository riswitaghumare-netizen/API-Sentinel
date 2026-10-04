from typing import Optional
from datetime import datetime
from pydantic import BaseModel, EmailStr
from app.core.rbac import Role


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: Optional[Role] = Role.SECURITY_ANALYST
    organization_name: Optional[str] = "Default Organization"


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "UserSummaryResponse"


class UserSummaryResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: Role
    organization_id: Optional[str] = None
    is_active: bool
    created_at: datetime


class UserSessionResponse(BaseModel):
    id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_info: Optional[str] = None
    created_at: datetime
    expires_at: datetime
    is_current: bool = False
