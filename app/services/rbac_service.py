from uuid import UUID

from sqlalchemy import delete, insert, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.permission import Permission
from app.models.role import Role
from app.models.role_permission import RolePermission
from app.schemas.permission import PermissionCreateRequest
from app.schemas.role import RoleCreateRequest, RoleUpdateRequest
from app.utils.errors import AppError


class RBACService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def list_roles(self) -> list[Role]:
        result = await self.session.scalars(select(Role).options(selectinload(Role.permissions)).order_by(Role.name))
        return list(result.all())

    async def get_role(self, role_id: UUID) -> Role:
        role = await self.session.scalar(select(Role).options(selectinload(Role.permissions)).where(Role.id == role_id))
        if role is None:
            raise AppError(404, "ROLE_NOT_FOUND", "Role not found.")
        return role

    async def create_role(self, payload: RoleCreateRequest) -> Role:
        name = payload.name.strip()
        existing = await self.session.scalar(select(Role).where(Role.name == name))
        if existing is not None:
            raise AppError(400, "ROLE_ALREADY_EXISTS", "A role with this name already exists.")
        role = Role(name=name, description=payload.description.strip())
        self.session.add(role)
        await self.session.flush()
        if payload.permission_ids:
            await self._replace_role_permissions(role.id, payload.permission_ids)
        await self.session.commit()
        return await self.get_role(role.id)

    async def update_role(self, role_id: UUID, payload: RoleUpdateRequest) -> Role:
        role = await self.get_role(role_id)
        if payload.name is not None:
            role.name = payload.name.strip()
        if payload.description is not None:
            role.description = payload.description.strip()
        if payload.permission_ids is not None:
            await self._replace_role_permissions(role.id, payload.permission_ids)
        await self.session.commit()
        return await self.get_role(role.id)

    async def delete_role(self, role_id: UUID) -> None:
        role = await self.get_role(role_id)
        await self.session.delete(role)
        await self.session.commit()

    async def add_permissions(self, role_id: UUID, permission_ids: list[UUID]) -> Role:
        role = await self.get_role(role_id)
        permissions = await self._get_permissions(permission_ids)
        existing_ids = {permission.id for permission in role.permissions}
        rows = [
            {"role_id": role.id, "permission_id": permission.id}
            for permission in permissions
            if permission.id not in existing_ids
        ]
        if rows:
            await self.session.execute(insert(RolePermission), rows)
        await self.session.commit()
        return await self.get_role(role.id)

    async def remove_permission(self, role_id: UUID, permission_id: UUID) -> Role:
        role = await self.get_role(role_id)
        if permission_id not in {permission.id for permission in role.permissions}:
            raise AppError(404, "ROLE_PERMISSION_NOT_FOUND", "Permission is not assigned to this role.")
        await self.session.execute(delete(RolePermission).where(RolePermission.role_id == role.id, RolePermission.permission_id == permission_id))
        await self.session.commit()
        return await self.get_role(role.id)

    async def list_permissions(self) -> list[Permission]:
        result = await self.session.scalars(select(Permission).order_by(Permission.name))
        return list(result.all())

    async def create_permission(self, payload: PermissionCreateRequest) -> Permission:
        name = payload.name.strip()
        existing = await self.session.scalar(select(Permission).where(Permission.name == name))
        if existing is not None:
            raise AppError(400, "PERMISSION_ALREADY_EXISTS", "A permission with this name already exists.")
        permission = Permission(name=name, description=payload.description.strip())
        self.session.add(permission)
        await self.session.commit()
        await self.session.refresh(permission)
        return permission

    async def _replace_role_permissions(self, role_id: UUID, permission_ids: list[UUID]) -> None:
        permissions = await self._get_permissions(permission_ids)
        await self.session.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
        if permissions:
            await self.session.execute(insert(RolePermission), [{"role_id": role_id, "permission_id": permission.id} for permission in permissions])

    async def _get_permissions(self, permission_ids: list[UUID]) -> list[Permission]:
        if not permission_ids:
            return []
        result = await self.session.scalars(select(Permission).where(Permission.id.in_(permission_ids)))
        permissions = list(result.all())
        if len(permissions) != len(set(permission_ids)):
            raise AppError(404, "PERMISSION_NOT_FOUND", "One or more permissions were not found.")
        return permissions
