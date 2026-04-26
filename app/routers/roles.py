from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db_session
from app.middleware.auth import get_current_user
from app.models.user import User
from app.schemas.auth import MessageResponse
from app.schemas.role import RoleCreateRequest, RoleListResponse, RolePermissionAssignRequest, RoleResponse, RoleUpdateRequest
from app.services.rbac_service import RBACService
from app.services.user_service import UserService
from app.utils.errors import AppError


router = APIRouter(prefix="/api/v1/roles", tags=["roles"])


@router.get("", response_model=RoleListResponse)
async def list_roles(
    session: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    if not UserService.has_permission(current_user, "roles:read"):
        raise AppError(403, "FORBIDDEN", "You do not have permission to view roles.")
    roles = await RBACService(session).list_roles()
    return {"data": {"items": roles}}


@router.post("", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    payload: RoleCreateRequest,
    session: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    if not UserService.has_role(current_user, "super_admin"):
        raise AppError(403, "FORBIDDEN", "You do not have permission to create roles.")
    role = await RBACService(session).create_role(payload)
    return {"data": role}


@router.get("/{role_id}", response_model=RoleResponse)
async def get_role(
    role_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    if not UserService.has_permission(current_user, "roles:read"):
        raise AppError(403, "FORBIDDEN", "You do not have permission to view roles.")
    role = await RBACService(session).get_role(role_id)
    return {"data": role}


@router.patch("/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: UUID,
    payload: RoleUpdateRequest,
    session: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    if not UserService.has_role(current_user, "super_admin"):
        raise AppError(403, "FORBIDDEN", "You do not have permission to update roles.")
    role = await RBACService(session).update_role(role_id, payload)
    return {"data": role}


@router.delete("/{role_id}", response_model=MessageResponse)
async def delete_role(
    role_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    if not UserService.has_role(current_user, "super_admin"):
        raise AppError(403, "FORBIDDEN", "You do not have permission to delete roles.")
    await RBACService(session).delete_role(role_id)
    return {"data": {"message": "Role deleted successfully."}}


@router.post("/{role_id}/permissions", response_model=RoleResponse)
async def add_role_permissions(
    role_id: UUID,
    payload: RolePermissionAssignRequest,
    session: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    if not UserService.has_role(current_user, "super_admin"):
        raise AppError(403, "FORBIDDEN", "You do not have permission to assign role permissions.")
    role = await RBACService(session).add_permissions(role_id, payload.permission_ids)
    return {"data": role}


@router.delete("/{role_id}/permissions/{permission_id}", response_model=RoleResponse)
async def remove_role_permission(
    role_id: UUID,
    permission_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    if not UserService.has_role(current_user, "super_admin"):
        raise AppError(403, "FORBIDDEN", "You do not have permission to remove role permissions.")
    role = await RBACService(session).remove_permission(role_id, permission_id)
    return {"data": role}
