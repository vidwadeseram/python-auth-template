from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db_session
from app.middleware.auth import get_current_user
from app.models.user import User
from app.schemas.auth import MessageResponse
from app.schemas.user import UserDetailResponse, UserListResponse, UserUpdateRequest
from app.services.user_service import UserService
from app.utils.errors import AppError


router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.get("", response_model=UserListResponse)
async def list_users(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=10, ge=1, le=100),
    session: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    if not UserService.has_permission(current_user, "users:read"):
        raise AppError(403, "FORBIDDEN", "You do not have permission to view users.")
    items, total = await UserService(session).list_users(page, page_size)
    return {"data": {"items": items, "total": total, "page": page, "page_size": page_size}}


@router.get("/{user_id}", response_model=UserDetailResponse)
async def get_user(
    user_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    if current_user.id != user_id and not UserService.has_permission(current_user, "users:read"):
        raise AppError(403, "FORBIDDEN", "You do not have permission to view this user.")
    user = await UserService(session).get_user(user_id)
    return {"data": UserService.serialize_user(user)}


@router.patch("/{user_id}", response_model=UserDetailResponse)
async def update_user(
    user_id: UUID,
    payload: UserUpdateRequest,
    session: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    user = await UserService(session).update_user(current_user, user_id, payload)
    return {"data": user}


@router.delete("/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    await UserService(session).delete_user(current_user, user_id)
    return {"data": {"message": "User deleted successfully."}}
