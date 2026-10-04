import hashlib
from datetime import datetime, timezone, timedelta
from typing import List
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.core.exceptions import UnauthorizedException, ValidationException, NotFoundException
from app.core.rbac import Role
from app.core.config import settings
from app.models.user import User, UserSession
from app.models.organization import Organization, Project
from app.schemas.base import ApiResponse
from app.schemas.auth import (
    UserCreate,
    UserLogin,
    TokenResponse,
    UserSummaryResponse,
    RefreshTokenRequest,
    UserSessionResponse,
)
from app.api.deps import get_current_user
from app.services.audit_service import AuditService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=ApiResponse[TokenResponse])
async def register(req: UserCreate, request: Request, db: AsyncSession = Depends(get_db)):
    """Registers a new user and creates default Organization & Project if first user."""
    # Check existing user
    stmt = select(User).where(User.email == req.email.lower().strip())
    existing = (await db.execute(stmt)).scalars().first()
    if existing:
        raise ValidationException("An account with this email address already exists.")

    # Check if first user in the system (grant SUPER_ADMIN)
    users_count_stmt = select(User)
    all_users = (await db.execute(users_count_stmt)).scalars().all()
    user_role = Role.SUPER_ADMIN if len(all_users) == 0 else (req.role or Role.SECURITY_ANALYST)

    # Create Organization if none exists or custom specified
    org_stmt = select(Organization)
    org = (await db.execute(org_stmt)).scalars().first()
    if not org:
        org = Organization(
            name=req.organization_name or "Default Enterprise Org",
            slug="default-org",
            description="Default Organization for API Security Monitoring",
        )
        db.add(org)
        await db.flush()

        # Create Default Project
        proj = Project(
            organization_id=org.id,
            name="Core Platform APIs",
            slug="core-platform",
            description="Primary project for monitoring production & staging API endpoints",
        )
        db.add(proj)
        await db.flush()

    new_user = User(
        email=req.email.lower().strip(),
        hashed_password=get_password_hash(req.password),
        full_name=req.full_name,
        role=user_role,
        is_active=True,
        is_verified=True,
        organization_id=org.id,
        created_at=datetime.now(timezone.utc),
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Issue tokens
    access_token = create_access_token(subject=new_user.id, role=new_user.role.value, org_id=org.id)
    refresh_token = create_refresh_token(subject=new_user.id)

    # Store user session
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Browser Client")
    
    session = UserSession(
        user_id=new_user.id,
        token_hash=token_hash,
        ip_address=client_ip,
        user_agent=user_agent[:250],
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(session)
    await db.commit()

    # Log audit
    await AuditService.log_event(
        db=db,
        action="USER_REGISTERED",
        resource_type="USER",
        resource_id=new_user.id,
        user_id=new_user.id,
        user_email=new_user.email,
        ip_address=client_ip,
    )

    user_summary = UserSummaryResponse(
        id=new_user.id,
        email=new_user.email,
        full_name=new_user.full_name,
        role=new_user.role,
        organization_id=new_user.organization_id,
        is_active=new_user.is_active,
        created_at=new_user.created_at,
    )

    token_data = TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user_summary,
    )
    return ApiResponse(data=token_data)


@router.post("/login", response_model=ApiResponse[TokenResponse])
async def login(req: UserLogin, request: Request, db: AsyncSession = Depends(get_db)):
    """Authenticates user credentials and issues new JWT tokens."""
    stmt = select(User).where(User.email == req.email.lower().strip())
    user = (await db.execute(stmt)).scalars().first()

    client_ip = request.client.host if request.client else "127.0.0.1"

    if not user or not verify_password(req.password, user.hashed_password):
        await AuditService.log_event(
            db=db,
            action="LOGIN_FAILED",
            resource_type="AUTH",
            user_email=req.email,
            status="DENIED",
            ip_address=client_ip,
        )
        raise UnauthorizedException("Invalid email address or password.")

    if not user.is_active:
        raise UnauthorizedException("Your account has been deactivated.")

    # Update last login
    user.last_login_at = datetime.now(timezone.utc)

    # Issue tokens
    access_token = create_access_token(subject=user.id, role=user.role.value, org_id=user.organization_id)
    refresh_token = create_refresh_token(subject=user.id)

    # Store session
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    user_agent = request.headers.get("user-agent", "Browser Client")
    session = UserSession(
        user_id=user.id,
        token_hash=token_hash,
        ip_address=client_ip,
        user_agent=user_agent[:250],
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(session)
    await db.commit()

    await AuditService.log_event(
        db=db,
        action="LOGIN_SUCCESS",
        resource_type="AUTH",
        user_id=user.id,
        user_email=user.email,
        ip_address=client_ip,
    )

    user_summary = UserSummaryResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        organization_id=user.organization_id,
        is_active=user.is_active,
        created_at=user.created_at,
    )

    token_data = TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user_summary,
    )
    return ApiResponse(data=token_data)


@router.post("/refresh", response_model=ApiResponse[TokenResponse])
async def refresh_tokens(req: RefreshTokenRequest, db: AsyncSession = Depends(get_db)):
    """Rotates refresh token and issues a new access token."""
    payload = decode_token(req.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise UnauthorizedException("Invalid or expired refresh token.")

    user_id = payload.get("sub")
    stmt = select(User).where(User.id == user_id)
    user = (await db.execute(stmt)).scalars().first()
    if not user or not user.is_active:
        raise UnauthorizedException("User account not active.")

    token_hash = hashlib.sha256(req.refresh_token.encode()).hexdigest()
    session_stmt = select(UserSession).where(
        UserSession.token_hash == token_hash,
        UserSession.is_revoked == False,
    )
    session = (await db.execute(session_stmt)).scalars().first()
    if not session or session.expires_at < datetime.now(timezone.utc):
        raise UnauthorizedException("Session is invalid or expired.")

    # Rotate session
    session.is_revoked = True
    new_refresh = create_refresh_token(subject=user.id)
    new_access = create_access_token(subject=user.id, role=user.role.value, org_id=user.organization_id)
    new_hash = hashlib.sha256(new_refresh.encode()).hexdigest()

    new_session = UserSession(
        user_id=user.id,
        token_hash=new_hash,
        ip_address=session.ip_address,
        user_agent=session.user_agent,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(new_session)
    await db.commit()

    user_summary = UserSummaryResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        organization_id=user.organization_id,
        is_active=user.is_active,
        created_at=user.created_at,
    )

    return ApiResponse(
        data=TokenResponse(
            access_token=new_access,
            refresh_token=new_refresh,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=user_summary,
        )
    )


@router.get("/me", response_model=ApiResponse[UserSummaryResponse])
async def get_me(current_user: User = Depends(get_current_user)):
    """Returns profile for current authenticated user."""
    return ApiResponse(
        data=UserSummaryResponse(
            id=current_user.id,
            email=current_user.email,
            full_name=current_user.full_name,
            role=current_user.role,
            organization_id=current_user.organization_id,
            is_active=current_user.is_active,
            created_at=current_user.created_at,
        )
    )


@router.get("/sessions", response_model=ApiResponse[List[UserSessionResponse]])
async def list_sessions(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Lists active login sessions for current user."""
    stmt = (
        select(UserSession)
        .where(UserSession.user_id == current_user.id, UserSession.is_revoked == False)
        .order_by(UserSession.created_at.desc())
    )
    sessions = (await db.execute(stmt)).scalars().all()
    
    session_list = [
        UserSessionResponse(
            id=s.id,
            ip_address=s.ip_address,
            user_agent=s.user_agent,
            device_info=s.device_info,
            created_at=s.created_at,
            expires_at=s.expires_at,
        )
        for s in sessions
    ]
    return ApiResponse(data=session_list)


@router.post("/sessions/{session_id}/revoke", response_model=ApiResponse[dict])
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revokes a specific session."""
    stmt = select(UserSession).where(UserSession.id == session_id, UserSession.user_id == current_user.id)
    session = (await db.execute(stmt)).scalars().first()
    if not session:
        raise NotFoundException("Session", session_id)
    
    session.is_revoked = True
    await db.commit()
    return ApiResponse(data={"message": "Session revoked successfully."})
