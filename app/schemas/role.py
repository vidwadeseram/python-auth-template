from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.permission import PermissionRead


class RoleSummaryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str
    created_at: datetime


class RoleRead(RoleSummaryRead):
    permissions: list[PermissionRead] = Field(default_factory=list)


class RoleCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=50)
    description: str = Field(min_length=1, max_length=255)
    permission_ids: list[UUID] = Field(default_factory=list)


class RoleUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=50)
    description: str | None = Field(default=None, min_length=1, max_length=255)
    permission_ids: list[UUID] | None = None


class RolePermissionAssignRequest(BaseModel):
    permission_ids: list[UUID] = Field(min_length=1)


class RoleListData(BaseModel):
    items: list[RoleRead]


class RoleListResponse(BaseModel):
    data: RoleListData


class RoleResponse(BaseModel):
    data: RoleRead
