from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.auth import has_permission, has_role
from app.middleware.ratelimit import RateLimitMiddleware
from app.models.user import User

TEST_SECRET = "test-secret-key-for-unit-tests-only"
TEST_ALGO = "HS256"


def _make_access_token(user_id: str, secret: str = TEST_SECRET, expire_delta: timedelta = timedelta(minutes=15)) -> str:
    return jwt.encode(
        {"sub": user_id, "exp": datetime.now(UTC) + expire_delta},
        secret,
        algorithm=TEST_ALGO,
    )


def _make_mock_role(name: str, permission_names: list[str] | None = None) -> MagicMock:
    role = MagicMock()
    role.name = name
    role.permissions = []
    if permission_names:
        for pname in permission_names:
            perm = MagicMock()
            perm.name = pname
            role.permissions.append(perm)
    return role


def _make_user_with_roles(role_names: list[str], permission_names: list[str] | None = None) -> MagicMock:
    user = MagicMock(spec=User)
    user.roles = [_make_mock_role(rname, permission_names) for rname in role_names]
    return user


class TestRateLimitMiddleware:
    @pytest.fixture
    def rate_limited_app(self):
        app = FastAPI()
        app.add_middleware(RateLimitMiddleware, rate=100.0, burst=2, prefix="/api/v1/auth")

        @app.get("/api/v1/auth/ping")
        async def ping():
            return {"ok": True}

        @app.get("/health")
        async def health():
            return {"ok": True}

        return TestClient(app, raise_server_exceptions=False)

    def test_requests_within_burst_pass(self, rate_limited_app):
        r1 = rate_limited_app.get("/api/v1/auth/ping")
        r2 = rate_limited_app.get("/api/v1/auth/ping")
        assert r1.status_code == 200
        assert r2.status_code == 200

    def test_requests_over_burst_get_429(self, rate_limited_app):
        rate_limited_app.get("/api/v1/auth/ping")
        rate_limited_app.get("/api/v1/auth/ping")
        r3 = rate_limited_app.get("/api/v1/auth/ping")
        assert r3.status_code == 429
        assert r3.json()["error"]["code"] == "RATE_LIMITED"

    def test_non_auth_path_not_rate_limited(self, rate_limited_app):
        for _ in range(10):
            r = rate_limited_app.get("/health")
            assert r.status_code == 200

    def test_rate_limit_response_has_correct_structure(self, rate_limited_app):
        rate_limited_app.get("/api/v1/auth/ping")
        rate_limited_app.get("/api/v1/auth/ping")
        r = rate_limited_app.get("/api/v1/auth/ping")
        body = r.json()
        assert "error" in body
        assert "code" in body["error"]
        assert "message" in body["error"]

    def test_allow_refills_over_time(self):
        app = FastAPI()
        app.add_middleware(RateLimitMiddleware, rate=0.0, burst=1, prefix="/api/v1/auth")

        @app.get("/api/v1/auth/ping")
        async def ping():
            return {"ok": True}

        client = TestClient(app, raise_server_exceptions=False)
        r1 = client.get("/api/v1/auth/ping")
        assert r1.status_code == 200
        r2 = client.get("/api/v1/auth/ping")
        assert r2.status_code == 429


class TestAuthMiddlewareFunctions:
    def test_has_role_returns_true_when_role_present(self):
        user = _make_user_with_roles(["admin", "user"])
        assert has_role(user, "admin") is True

    def test_has_role_returns_false_when_role_absent(self):
        user = _make_user_with_roles(["user"])
        assert has_role(user, "admin") is False

    def test_has_role_empty_roles(self):
        user = _make_user_with_roles([])
        assert has_role(user, "admin") is False

    def test_has_permission_returns_true_when_present(self):
        user = _make_user_with_roles(["admin"], ["read:users", "write:users"])
        assert has_permission(user, "read:users") is True

    def test_has_permission_returns_false_when_absent(self):
        user = _make_user_with_roles(["admin"], ["read:users"])
        assert has_permission(user, "delete:users") is False

    def test_has_permission_empty_permissions(self):
        user = _make_user_with_roles(["user"])
        assert has_permission(user, "read:users") is False


from app.deps import get_db_session
from app.main import app as _app


class TestGetCurrentUserDependency:
    @pytest.fixture
    def auth_app(self, mock_session, sample_user):
        async def _override_db():
            yield mock_session

        _app.dependency_overrides[get_db_session] = _override_db
        mock_session.scalar = AsyncMock(return_value=sample_user)
        client = TestClient(_app, raise_server_exceptions=False)
        yield client, mock_session
        _app.dependency_overrides.clear()

    def test_missing_auth_header_returns_401(self, auth_app):
        client, _ = auth_app
        r = client.get("/api/v1/users/me")
        assert r.status_code == 401

    def test_invalid_token_returns_401(self, auth_app):
        client, _ = auth_app
        r = client.get("/api/v1/users/me", headers={"Authorization": "Bearer not-a-real-token"})
        assert r.status_code == 401

    def test_valid_token_with_no_user_in_db_returns_401(self, auth_app, sample_user):
        client, mock_session = auth_app
        mock_session.scalar = AsyncMock(return_value=None)
        token = _make_access_token(str(sample_user.id))
        r = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401
