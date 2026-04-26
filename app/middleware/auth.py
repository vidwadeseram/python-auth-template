from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.deps import get_db_session
from app.models.role import Role
from app.models.user import User
from app.services.token_service import TokenService
from app.utils.errors import AppError


bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_db_session),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AppError(401, "AUTHENTICATION_REQUIRED", "Authentication credentials were not provided.")

    payload = TokenService().decode_token(credentials.credentials, expected_type="access")
    user = await session.scalar(
        select(User)
        .options(selectinload(User.roles).selectinload(Role.permissions))
        .where(User.id == payload.subject, User.is_active.is_(True), User.deleted_at.is_(None))
    )
    if user is None:
        raise AppError(401, "USER_NOT_FOUND", "Authenticated user was not found.")
    return user


def has_role(user: User, role_name: str) -> bool:
    return any(role.name == role_name for role in user.roles)


def has_permission(user: User, permission_name: str) -> bool:
    return any(permission.name == permission_name for role in user.roles for permission in role.permissions)


def require_role(role_name: str):
    async def dependency(current_user: User = Depends(get_current_user)) -> User:
        if not has_role(current_user, role_name):
            raise AppError(403, "FORBIDDEN", "You do not have the required role.")
        return current_user

    return dependency


def require_permission(permission_name: str):
    async def dependency(current_user: User = Depends(get_current_user)) -> User:
        if not has_permission(current_user, permission_name):
            raise AppError(403, "FORBIDDEN", "You do not have the required permission.")
        return current_user

    return dependency
