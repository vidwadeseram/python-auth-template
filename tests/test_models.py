from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.schemas.auth import LoginRequest, RegisterRequest, TokenData
from app.schemas.user import UserRead, UserUpdateRequest


class TestUserModelFields:
    def test_user_instantiation_with_required_fields(self, sample_user):
        assert sample_user.email == "alice@example.com"
        assert sample_user.first_name == "Alice"
        assert sample_user.last_name == "Smith"
        assert sample_user.is_active is True
        assert sample_user.is_verified is True

    def test_user_has_uuid_id(self, sample_user):
        assert isinstance(sample_user.id, uuid.UUID)

    def test_user_deleted_at_defaults_to_none(self, sample_user):
        assert sample_user.deleted_at is None

    def test_user_password_hash_is_stored(self, sample_user):
        assert sample_user.password_hash.startswith("$2b$") or sample_user.password_hash.startswith("$2a$")

    def test_user_roles_list_is_empty_by_default(self, sample_user):
        assert sample_user.roles == []


class TestRegisterRequestValidation:
    def test_valid_payload_passes(self):
        req = RegisterRequest(
            email="bob@example.com",
            password="StrongPass1!",
            first_name="Bob",
            last_name="Jones",
        )
        assert req.email == "bob@example.com"

    def test_invalid_email_raises(self):
        with pytest.raises(ValidationError):
            RegisterRequest(
                email="not-an-email",
                password="StrongPass1!",
                first_name="Bob",
                last_name="Jones",
            )

    def test_password_too_short_raises(self):
        with pytest.raises(ValidationError):
            RegisterRequest(
                email="bob@example.com",
                password="short",
                first_name="Bob",
                last_name="Jones",
            )

    def test_password_too_long_raises(self):
        with pytest.raises(ValidationError):
            RegisterRequest(
                email="bob@example.com",
                password="x" * 129,
                first_name="Bob",
                last_name="Jones",
            )

    def test_empty_first_name_raises(self):
        with pytest.raises(ValidationError):
            RegisterRequest(
                email="bob@example.com",
                password="StrongPass1!",
                first_name="",
                last_name="Jones",
            )

    def test_empty_last_name_raises(self):
        with pytest.raises(ValidationError):
            RegisterRequest(
                email="bob@example.com",
                password="StrongPass1!",
                first_name="Bob",
                last_name="",
            )

    def test_email_domain_is_normalised_by_pydantic(self):
        req = RegisterRequest(
            email="BOB@EXAMPLE.COM",
            password="StrongPass1!",
            first_name="Bob",
            last_name="Jones",
        )
        assert req.email.endswith("@example.com")


class TestLoginRequestValidation:
    def test_valid_payload_passes(self):
        req = LoginRequest(email="alice@example.com", password="Password1!")
        assert req.email == "alice@example.com"

    def test_invalid_email_raises(self):
        with pytest.raises(ValidationError):
            LoginRequest(email="bad-email", password="Password1!")

    def test_short_password_raises(self):
        with pytest.raises(ValidationError):
            LoginRequest(email="alice@example.com", password="short")


class TestTokenDataSchema:
    def test_token_data_defaults_to_bearer(self):
        td = TokenData(
            access_token="acc",
            refresh_token="ref",
            expires_in=900,
        )
        assert td.token_type == "Bearer"

    def test_token_data_stores_expires_in(self):
        td = TokenData(access_token="acc", refresh_token="ref", expires_in=900)
        assert td.expires_in == 900


class TestUserReadSchema:
    def test_user_read_from_orm(self, sample_user):
        read = UserRead.model_validate(sample_user)
        assert str(read.id) == str(sample_user.id)
        assert read.email == sample_user.email
        assert read.first_name == sample_user.first_name
        assert read.is_active is True
        assert read.is_verified is True

    def test_user_read_deleted_at_none(self, sample_user):
        read = UserRead.model_validate(sample_user)
        assert read.deleted_at is None


class TestUserUpdateRequestValidation:
    def test_all_fields_optional(self):
        req = UserUpdateRequest()
        assert req.first_name is None
        assert req.last_name is None
        assert req.password is None
        assert req.is_active is None

    def test_first_name_too_long_raises(self):
        with pytest.raises(ValidationError):
            UserUpdateRequest(first_name="x" * 101)

    def test_password_too_short_raises(self):
        with pytest.raises(ValidationError):
            UserUpdateRequest(password="short")

    def test_valid_partial_update(self):
        req = UserUpdateRequest(first_name="Charlie", is_active=False)
        assert req.first_name == "Charlie"
        assert req.is_active is False
