from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

# These env vars must be set before any app module is imported because
# get_settings() is lru_cache'd and reads them at first call.
TEST_JWT_SECRET = "test-secret-key-for-unit-tests-only"
TEST_DATABASE_URL = "postgresql+asyncpg://test:test@localhost/test"

os.environ.setdefault("DATABASE_URL", TEST_DATABASE_URL)
os.environ.setdefault("JWT_SECRET", TEST_JWT_SECRET)
os.environ.setdefault("JWT_ACCESS_EXPIRE_MINUTES", "15")
os.environ.setdefault("JWT_REFRESH_EXPIRE_DAYS", "7")
os.environ.setdefault("SMTP_HOST", "localhost")
os.environ.setdefault("SMTP_PORT", "1025")
os.environ.setdefault("SMTP_SENDER", "test@example.com")
os.environ.setdefault("APP_PORT", "8001")

import sqlalchemy.ext.asyncio as _sa_async
import sys
import types

_sa_async.create_async_engine = MagicMock(return_value=MagicMock())  # type: ignore[assignment]

import app.models.role_permission as _rp_module
import app.models.user_role as _ur_module

_fake_rbac = types.ModuleType("app.models.rbac")
_fake_rbac.RolePermission = _rp_module.RolePermission  # type: ignore[attr-defined]
_fake_rbac.UserRole = _ur_module.UserRole  # type: ignore[attr-defined]
sys.modules["app.models.rbac"] = _fake_rbac

from app.config import Settings
from app.main import app as _fastapi_app  # noqa: F401 — registers all models once
from app.models.user import User
from app.utils.security import hash_password


@pytest.fixture(scope="session", autouse=True)
def patch_settings():
    test_settings = Settings(
        DATABASE_URL=TEST_DATABASE_URL,
        JWT_SECRET=TEST_JWT_SECRET,
        JWT_ACCESS_EXPIRE_MINUTES=15,
        JWT_REFRESH_EXPIRE_DAYS=7,
        SMTP_HOST="localhost",
        SMTP_PORT=1025,
        SMTP_SENDER="test@example.com",
        APP_PORT=8001,
    )
    with patch("app.config.get_settings", return_value=test_settings), patch(
        "app.services.token_service.get_settings", return_value=test_settings
    ):
        yield test_settings


@pytest.fixture
def mock_session() -> AsyncMock:
    session = AsyncMock(spec=AsyncSession)
    session.scalar = AsyncMock(return_value=None)
    session.execute = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    return session


@pytest.fixture
def sample_user() -> User:
    user = User(
        id=uuid.uuid4(),
        email="alice@example.com",
        password_hash=hash_password("Password1!"),
        first_name="Alice",
        last_name="Smith",
        is_active=True,
        is_verified=True,
        deleted_at=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    user.roles = []
    return user


@pytest.fixture
def test_client(mock_session: AsyncMock) -> TestClient:
    from app.deps import get_db_session
    from app.main import app

    async def _override_db() -> AsyncGenerator[AsyncMock, None]:
        yield mock_session

    app.dependency_overrides[get_db_session] = _override_db
    client = TestClient(app, raise_server_exceptions=False)
    yield client
    app.dependency_overrides.clear()
