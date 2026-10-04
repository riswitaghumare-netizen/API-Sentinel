from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel


class OrganizationCreate(BaseModel):
    name: str
    description: Optional[str] = None


class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str] = None
    created_at: datetime


class ProjectCreate(BaseModel):
    organization_id: Optional[str] = None
    name: str
    description: Optional[str] = None


class ProjectResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    slug: str
    description: Optional[str] = None
    apis_count: int = 0
    created_at: datetime
