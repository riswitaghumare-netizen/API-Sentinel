from typing import Optional, List, Callable
from fastapi import Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import decode_token
from app.core.rbac import Role, Permission, has_permission
from app.core.exceptions import UnauthorizedException, ForbiddenException
from app.models.user import User

security_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    auth_credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Validates JWT access token and returns authenticated User."""
    if not auth_credentials:
        raise UnauthorizedException("Authentication token required.")
    
    token = auth_credentials.credentials
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise UnauthorizedException("Invalid or expired access token.")
    
    user_id = payload.get("sub")
    if not user_id:
        raise UnauthorizedException("Malformed token subject.")
    
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()
    
    if not user:
        raise UnauthorizedException("User account not found.")
    if not user.is_active:
        raise ForbiddenException("User account is deactivated.")
        
    return user


def require_roles(allowed_roles: List[Role]):
    """Enforces role-based authorization for endpoint routes."""
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role == Role.SUPER_ADMIN:
            return current_user
        if current_user.role not in allowed_roles:
            raise ForbiddenException(f"Action requires one of the following roles: {[r.value for r in allowed_roles]}")
        return current_user
    return role_checker


def require_permission(permission: Permission):
    """Enforces specific granular permission checks."""
    def perm_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role == Role.SUPER_ADMIN:
            return current_user
        if not has_permission(current_user.role, permission):
            raise ForbiddenException(f"Missing required permission: {permission.value}")
        return current_user
    return perm_checker
