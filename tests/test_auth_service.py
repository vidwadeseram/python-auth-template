from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest

from app.config import Settings
from app.models.refresh_token import RefreshToken
from app.schemas.auth import TokenData
from app.services.token_service import TokenService
from app.utils.errors import AppError
from app.utils.security import hash_password, verify_password

TEST_SECRET = "test-secret-key-for-unit-tests-only"
TEST_ALGO = "HS256"


@pytest.fixture
def token_service():
    svc = TokenService.__new__(TokenService)
    svc.settings = Settings(
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        JWT_SECRET=TEST_SECRET,
        JWT_ACCESS_EXPIRE_MINUTES=15,
        JWT_REFRESH_EXPIRE_DAYS=7,
        SMTP_HOST="localhost",
        SMTP_PORT=1025,
        SMTP_SENDER="test@example.com",
        APP_PORT=8001,
    )
    return svc


class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        hashed = hash_password("MySecret1!")
        assert hashed != "MySecret1!"

    def test_correct_password_verifies(self):
        hashed = hash_password("MySecret1!")
        assert verify_password("MySecret1!", hashed) is True

    def test_wrong_password_fails(self):
        hashed = hash_password("MySecret1!")
        assert verify_password("WrongPass1!", hashed) is False

    def test_empty_password_fails_against_real_hash(self):
        hashed = hash_password("MySecret1!")
        assert verify_password("", hashed) is False

    def test_different_hashes_for_same_password(self):
        h1 = hash_password("SamePass1!")
        h2 = hash_password("SamePass1!")
        assert h1 != h2

    def test_verify_with_invalid_hash_returns_false(self):
        assert verify_password("anything", "not-a-valid-hash") is False


class TestTokenCreation:
    def test_create_access_token_returns_string(self, token_service):
        token, expires_at = token_service.create_access_token(str(uuid.uuid4()))
        assert isinstance(token, str)
        assert len(token) > 0

    def test_access_token_expires_in_future(self, token_service):
        _, expires_at = token_service.create_access_token(str(uuid.uuid4()))
        assert expires_at > datetime.now(UTC)

    def test_create_refresh_token_returns_string(self, token_service):
        token, expires_at = token_service.create_refresh_token(str(uuid.uuid4()))
        assert isinstance(token, str)
        assert expires_at > datetime.now(UTC)

    def test_access_and_refresh_tokens_differ(self, token_service):
        uid = str(uuid.uuid4())
        access, _ = token_service.create_access_token(uid)
        refresh, _ = token_service.create_refresh_token(uid)
        assert access != refresh

    def test_create_verification_token_type(self, token_service):
        uid = str(uuid.uuid4())
        token, _ = token_service.create_verification_token(uid, "user@example.com")
        payload = jwt.decode(token, TEST_SECRET, algorithms=[TEST_ALGO])
        assert payload["type"] == "verify"

    def test_create_password_reset_token_type(self, token_service):
        uid = str(uuid.uuid4())
        token, _ = token_service.create_password_reset_token(uid, "user@example.com")
        payload = jwt.decode(token, TEST_SECRET, algorithms=[TEST_ALGO])
        assert payload["type"] == "reset"


class TestTokenDecoding:
    def test_decode_valid_access_token(self, token_service):
        uid = str(uuid.uuid4())
        token, _ = token_service.create_access_token(uid)
        result = token_service.decode_token(token, expected_type="access")
        assert str(result.subject) == uid

    def test_decode_valid_refresh_token(self, token_service):
        uid = str(uuid.uuid4())
        token, _ = token_service.create_refresh_token(uid)
        result = token_service.decode_token(token, expected_type="refresh")
        assert str(result.subject) == uid

    def test_expired_token_raises_app_error(self, token_service):
        uid = str(uuid.uuid4())
        expired_token = jwt.encode(
            {"sub": uid, "exp": datetime.now(UTC) - timedelta(seconds=1)},
            TEST_SECRET,
            algorithm=TEST_ALGO,
        )
        with pytest.raises(AppError) as exc_info:
            token_service.decode_token(expired_token)
        assert exc_info.value.code == "TOKEN_EXPIRED"

    def test_invalid_token_raises_app_error(self, token_service):
        with pytest.raises(AppError) as exc_info:
            token_service.decode_token("not.a.valid.token")
        assert exc_info.value.code == "INVALID_TOKEN"

    def test_wrong_token_type_raises_app_error(self, token_service):
        uid = str(uuid.uuid4())
        token, _ = token_service.create_access_token(uid)
        with pytest.raises(AppError) as exc_info:
            token_service.decode_token(token, expected_type="refresh")
        assert exc_info.value.code == "INVALID_TOKEN_TYPE"

    def test_token_missing_sub_raises_app_error(self, token_service):
        bad_token = jwt.encode(
            {"exp": datetime.now(UTC) + timedelta(minutes=5)},
            TEST_SECRET,
            algorithm=TEST_ALGO,
        )
        with pytest.raises(AppError) as exc_info:
            token_service.decode_token(bad_token)
        assert exc_info.value.code == "INVALID_TOKEN"


class TestHashToken:
    def test_hash_is_deterministic(self, token_service):
        t = "some-token-value"
        assert token_service.hash_token(t) == token_service.hash_token(t)

    def test_hash_matches_sha256(self, token_service):
        t = "some-token-value"
        expected = sha256(t.encode("utf-8")).hexdigest()
        assert token_service.hash_token(t) == expected

    def test_different_tokens_produce_different_hashes(self, token_service):
        assert token_service.hash_token("aaa") != token_service.hash_token("bbb")


class TestIssueTokenPair:
    @pytest.mark.asyncio
    async def test_issue_token_pair_returns_token_data(self, token_service):
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        uid = uuid.uuid4()
        result = await token_service.issue_token_pair(session, uid)
        assert isinstance(result, TokenData)
        assert result.token_type == "Bearer"
        assert result.access_token
        assert result.refresh_token

    @pytest.mark.asyncio
    async def test_issue_token_pair_adds_refresh_token_to_session(self, token_service):
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        uid = uuid.uuid4()
        await token_service.issue_token_pair(session, uid)
        session.add.assert_called_once()
        added = session.add.call_args[0][0]
        assert isinstance(added, RefreshToken)


class TestAuthServiceRegister:
    @pytest.mark.asyncio
    async def test_register_raises_if_email_exists(self, mock_session, sample_user):
        from app.models.role import Role
        from app.schemas.auth import RegisterRequest
        from app.services.auth_service import AuthService

        mock_session.scalar = AsyncMock(return_value=sample_user)
        svc = AuthService(mock_session)
        payload = RegisterRequest(
            email="alice@example.com",
            password="Password1!",
            first_name="Alice",
            last_name="Smith",
        )
        with pytest.raises(AppError) as exc_info:
            await svc.register(payload)
        assert exc_info.value.code == "EMAIL_ALREADY_EXISTS"

    @pytest.mark.asyncio
    async def test_register_raises_if_default_role_missing(self, mock_session):
        from app.schemas.auth import RegisterRequest
        from app.services.auth_service import AuthService

        mock_session.scalar = AsyncMock(side_effect=[None, None])
        svc = AuthService(mock_session)
        payload = RegisterRequest(
            email="new@example.com",
            password="Password1!",
            first_name="New",
            last_name="User",
        )
        with pytest.raises(AppError) as exc_info:
            await svc.register(payload)
        assert exc_info.value.code == "ROLE_NOT_FOUND"


class TestAuthServiceLogin:
    @pytest.mark.asyncio
    async def test_login_raises_on_wrong_password(self, mock_session, sample_user):
        from app.schemas.auth import LoginRequest
        from app.services.auth_service import AuthService

        mock_session.scalar = AsyncMock(return_value=sample_user)
        svc = AuthService(mock_session)
        payload = LoginRequest(email="alice@example.com", password="WrongPass1!")
        with pytest.raises(AppError) as exc_info:
            await svc.login(payload)
        assert exc_info.value.code == "INVALID_CREDENTIALS"

    @pytest.mark.asyncio
    async def test_login_raises_when_user_not_found(self, mock_session):
        from app.schemas.auth import LoginRequest
        from app.services.auth_service import AuthService

        mock_session.scalar = AsyncMock(return_value=None)
        svc = AuthService(mock_session)
        payload = LoginRequest(email="ghost@example.com", password="Password1!")
        with pytest.raises(AppError) as exc_info:
            await svc.login(payload)
        assert exc_info.value.code == "INVALID_CREDENTIALS"

    @pytest.mark.asyncio
    async def test_login_raises_when_user_inactive(self, mock_session, sample_user):
        from app.schemas.auth import LoginRequest
        from app.services.auth_service import AuthService

        sample_user.is_active = False
        mock_session.scalar = AsyncMock(return_value=sample_user)
        svc = AuthService(mock_session)
        payload = LoginRequest(email="alice@example.com", password="Password1!")
        with pytest.raises(AppError) as exc_info:
            await svc.login(payload)
        assert exc_info.value.code == "USER_INACTIVE"


class TestAuthServiceRefresh:
    @pytest.mark.asyncio
    async def test_refresh_raises_on_invalid_token(self, mock_session):
        from app.services.auth_service import AuthService

        svc = AuthService(mock_session)
        with pytest.raises(AppError) as exc_info:
            await svc.refresh("not-a-valid-token")
        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_raises_when_token_record_missing(self, mock_session, token_service):
        from app.services.auth_service import AuthService

        uid = uuid.uuid4()
        refresh_token, _ = token_service.create_refresh_token(str(uid))
        mock_session.scalar = AsyncMock(return_value=None)
        svc = AuthService(mock_session)
        svc.token_service = token_service
        with pytest.raises(AppError) as exc_info:
            await svc.refresh(refresh_token)
        assert exc_info.value.code == "INVALID_REFRESH_TOKEN"
