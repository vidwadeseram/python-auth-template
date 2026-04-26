from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.schemas.permission import PermissionRead
from app.schemas.role import RoleSummaryRead


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    first_name: str
    last_name: str
    is_active: bool
    is_verified: bool
    deleted_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class UserAccessRead(UserRead):
    roles: list[RoleSummaryRead] = Field(default_factory=list)
    permissions: list[PermissionRead] = Field(default_factory=list)


class UserResponse(BaseModel):
    data: UserRead


class UserDetailResponse(BaseModel):
    data: UserAccessRead


class UserListData(BaseModel):
    items: list[UserAccessRead]
    total: int
    page: int
    page_size: int


class UserListResponse(BaseModel):
    data: UserListData


class UserUpdateRequest(BaseModel):
    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name: str | None = Field(default=None, min_length=1, max_length=100)
    password: str | None = Field(default=None, min_length=8, max_length=128)
    is_active: bool | None = None
    is_verified: bool | None = None
    role_ids: list[UUID] | None = None
