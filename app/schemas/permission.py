from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class PermissionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    description: str
    created_at: datetime


class PermissionCreateRequest(BaseModel):
    name: str = Field(pattern=r"^[a-z_]+:[a-z_]+$", max_length=100)
    description: str = Field(min_length=1, max_length=255)


class PermissionListData(BaseModel):
    items: list[PermissionRead]


class PermissionListResponse(BaseModel):
    data: PermissionListData


class PermissionResponse(BaseModel):
    data: PermissionRead
