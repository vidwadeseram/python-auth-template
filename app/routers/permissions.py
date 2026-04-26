from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db_session
from app.middleware.auth import get_current_user
from app.models.user import User
from app.schemas.permission import PermissionCreateRequest, PermissionListResponse, PermissionResponse
from app.services.rbac_service import RBACService
from app.services.user_service import UserService
from app.utils.errors import AppError


router = APIRouter(prefix="/api/v1/permissions", tags=["permissions"])


@router.get("", response_model=PermissionListResponse)
async def list_permissions(
    session: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    if not UserService.has_permission(current_user, "permissions:read"):
        raise AppError(403, "FORBIDDEN", "You do not have permission to view permissions.")
    permissions = await RBACService(session).list_permissions()
    return {"data": {"items": permissions}}


@router.post("", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
async def create_permission(
    payload: PermissionCreateRequest,
    session: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    if not UserService.has_role(current_user, "super_admin"):
        raise AppError(403, "FORBIDDEN", "You do not have permission to create permissions.")
    permission = await RBACService(session).create_permission(payload)
    return {"data": permission}
