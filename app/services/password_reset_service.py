from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.services.token_service import TokenService
from app.utils.email import send_email
from app.utils.errors import AppError
from app.utils.security import hash_password


class PasswordResetService:
    def __init__(self, session: AsyncSession):
        self.session: AsyncSession = session
        self.token_service: TokenService = TokenService()

    async def request_reset(self, email: str) -> None:
        user = await self.session.scalar(select(User).where(User.email == email.lower()))
        if user is None:
            return

        reset_token, expires_at = self.token_service.create_password_reset_token(str(user.id), user.email)
        self.session.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=self.token_service.hash_token(reset_token),
                expires_at=expires_at,
            )
        )
        await self.session.commit()
        await send_email(
            recipient=user.email,
            subject="Password Reset",
            body=f"Your password reset token is: {reset_token}",
        )

    async def reset_password(self, token: str, new_password: str) -> None:
        payload = self.token_service.decode_token(token, expected_type="reset")
        token_record = await self.session.scalar(
            select(PasswordResetToken).where(
                PasswordResetToken.token_hash == self.token_service.hash_token(token),
                PasswordResetToken.user_id == payload.subject,
                PasswordResetToken.used_at.is_(None),
            )
        )
        if token_record is None or token_record.expires_at <= datetime.now(UTC):
            raise AppError(401, "INVALID_RESET_TOKEN", "Password reset token is invalid or expired.")

        user = await self.session.scalar(select(User).where(User.id == payload.subject))
        if user is None:
            raise AppError(404, "USER_NOT_FOUND", "User not found.")

        user.password_hash = hash_password(new_password)
        token_record.used_at = datetime.now(UTC)
        await self.session.commit()
