from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User
from app.schemas.permission import PermissionRead
from app.schemas.role import RoleSummaryRead
from app.schemas.user import UserAccessRead, UserUpdateRequest
from app.utils.errors import AppError
from app.utils.security import hash_password


class UserService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def list_users(self, page: int, page_size: int) -> tuple[list[UserAccessRead], int]:
        total = await self.session.scalar(select(func.count()).select_from(User).where(User.deleted_at.is_(None)))
        result = await self.session.scalars(
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .where(User.deleted_at.is_(None))
            .order_by(User.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return [self.serialize_user(user) for user in result.all()], int(total or 0)

    async def get_user(self, user_id: UUID) -> User:
        user = await self.session.scalar(
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .where(User.id == user_id, User.deleted_at.is_(None))
        )
        if user is None:
            raise AppError(404, "USER_NOT_FOUND", "User not found.")
        return user

    async def update_user(self, actor: User, user_id: UUID, payload: UserUpdateRequest) -> UserAccessRead:
        user = await self.get_user(user_id)
        is_self = actor.id == user.id
        if not is_self and not self.has_permission(actor, "users:write"):
            raise AppError(403, "FORBIDDEN", "You do not have permission to update this user.")
        if payload.first_name is not None:
            user.first_name = payload.first_name.strip()
        if payload.last_name is not None:
            user.last_name = payload.last_name.strip()
        if payload.password is not None:
            user.password_hash = hash_password(payload.password)
        admin_only_fields_requested = any(value is not None for value in (payload.is_active, payload.is_verified, payload.role_ids))
        if admin_only_fields_requested and is_self:
            raise AppError(403, "FORBIDDEN", "You cannot update admin-managed fields on your own account.")
        if payload.is_active is not None:
            user.is_active = payload.is_active
        if payload.is_verified is not None:
            user.is_verified = payload.is_verified
        if payload.role_ids is not None:
            if not self.has_role(actor, "super_admin"):
                raise AppError(403, "FORBIDDEN", "Only super admins can change user roles.")
            user.roles = await self._get_roles(payload.role_ids)
        await self.session.commit()
        return self.serialize_user(await self.get_user(user.id))

    async def delete_user(self, actor: User, user_id: UUID) -> None:
        if not self.has_permission(actor, "users:delete"):
            raise AppError(403, "FORBIDDEN", "You do not have permission to delete users.")
        user = await self.get_user(user_id)
        user.is_active = False
        user.deleted_at = datetime.now(UTC)
        await self.session.commit()

    @staticmethod
    def serialize_user(user: User) -> UserAccessRead:
        permissions_by_id: dict[UUID, Permission] = {}
        for role in user.roles:
            for permission in role.permissions:
                permissions_by_id[permission.id] = permission
        return UserAccessRead(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            is_active=user.is_active,
            is_verified=user.is_verified,
            deleted_at=user.deleted_at,
            created_at=user.created_at,
            updated_at=user.updated_at,
            roles=[RoleSummaryRead.model_validate(role, from_attributes=True) for role in user.roles],
            permissions=[PermissionRead.model_validate(permission, from_attributes=True) for permission in sorted(permissions_by_id.values(), key=lambda item: item.name)],
        )

    @staticmethod
    def has_permission(user: User, permission_name: str) -> bool:
        return any(permission.name == permission_name for role in user.roles for permission in role.permissions)

    @staticmethod
    def has_role(user: User, role_name: str) -> bool:
        return any(role.name == role_name for role in user.roles)

    async def _get_roles(self, role_ids: list[UUID]) -> list[Role]:
        if not role_ids:
            return []
        result = await self.session.scalars(select(Role).where(Role.id.in_(role_ids)))
        roles = list(result.all())
        if len(roles) != len(set(role_ids)):
            raise AppError(404, "ROLE_NOT_FOUND", "One or more roles were not found.")
        return roles
