from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.rbac import Role
from app.core.exceptions import NotFoundException, ForbiddenException
from app.models.user import User
from app.models.organization import Organization, Project
from app.schemas.base import ApiResponse
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationResponse,
    ProjectCreate,
    ProjectResponse,
)
from app.schemas.auth import UserSummaryResponse
from app.api.deps import get_current_user, require_roles

router = APIRouter(tags=["Organizations & Projects"])


@router.get("/organizations", response_model=ApiResponse[List[OrganizationResponse]])
async def list_organizations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists organizations accessible to current user."""
    stmt = select(Organization)
    if current_user.role != Role.SUPER_ADMIN and current_user.organization_id:
        stmt = stmt.where(Organization.id == current_user.organization_id)
        
    orgs = (await db.execute(stmt)).scalars().all()
    return ApiResponse(
        data=[
            OrganizationResponse(
                id=o.id,
                name=o.name,
                slug=o.slug,
                description=o.description,
                created_at=o.created_at,
            )
            for o in orgs
        ]
    )


@router.post("/organizations", response_model=ApiResponse[OrganizationResponse])
async def create_organization(
    req: OrganizationCreate,
    current_user: User = Depends(require_roles([Role.SUPER_ADMIN])),
    db: AsyncSession = Depends(get_db),
):
    """Creates a new organization (Super Admin only)."""
    slug = req.name.lower().replace(" ", "-").replace("/", "")
    org = Organization(name=req.name, slug=slug, description=req.description)
    db.add(org)
    await db.commit()
    await db.refresh(org)
    return ApiResponse(
        data=OrganizationResponse(
            id=org.id,
            name=org.name,
            slug=org.slug,
            description=org.description,
            created_at=org.created_at,
        )
    )


@router.get("/projects", response_model=ApiResponse[List[ProjectResponse]])
async def list_projects(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists projects in user's organization."""
    stmt = select(Project)
    if current_user.organization_id and current_user.role != Role.SUPER_ADMIN:
        stmt = stmt.where(Project.organization_id == current_user.organization_id)
        
    projects = (await db.execute(stmt)).scalars().all()
    return ApiResponse(
        data=[
            ProjectResponse(
                id=p.id,
                organization_id=p.organization_id,
                name=p.name,
                slug=p.slug,
                description=p.description,
                apis_count=len(p.apis) if p.apis else 0,
                created_at=p.created_at,
            )
            for p in projects
        ]
    )


@router.post("/projects", response_model=ApiResponse[ProjectResponse])
async def create_project(
    req: ProjectCreate,
    current_user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.SECURITY_ADMIN])),
    db: AsyncSession = Depends(get_db),
):
    """Creates a new project in the organization."""
    org_id = req.organization_id or current_user.organization_id
    if not org_id:
        raise NotFoundException("Organization ID required.")
        
    slug = req.name.lower().replace(" ", "-").replace("/", "")
    proj = Project(organization_id=org_id, name=req.name, slug=slug, description=req.description)
    db.add(proj)
    await db.commit()
    await db.refresh(proj)
    return ApiResponse(
        data=ProjectResponse(
            id=proj.id,
            organization_id=proj.organization_id,
            name=proj.name,
            slug=proj.slug,
            description=proj.description,
            apis_count=0,
            created_at=proj.created_at,
        )
    )


@router.get("/users", response_model=ApiResponse[List[UserSummaryResponse]])
async def list_users(
    current_user: User = Depends(require_roles([Role.SUPER_ADMIN, Role.SECURITY_ADMIN, Role.SECURITY_ANALYST])),
    db: AsyncSession = Depends(get_db),
):
    """Lists users in the organization for task assignment."""
    stmt = select(User).where(User.is_active == True)
    if current_user.organization_id and current_user.role != Role.SUPER_ADMIN:
        stmt = stmt.where(User.organization_id == current_user.organization_id)
        
    users = (await db.execute(stmt)).scalars().all()
    return ApiResponse(
        data=[
            UserSummaryResponse(
                id=u.id,
                email=u.email,
                full_name=u.full_name,
                role=u.role,
                organization_id=u.organization_id,
                is_active=u.is_active,
                created_at=u.created_at,
            )
            for u in users
        ]
    )
