from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.email_verification_token import EmailVerificationToken
from app.models.user import User
from app.services.token_service import TokenService
from app.utils.email import send_email
from app.utils.errors import AppError


class VerificationService:
    def __init__(self, session: AsyncSession):
        self.session: AsyncSession = session
        self.token_service: TokenService = TokenService()

    async def send_verification_email(self, user: User) -> None:
        verification_token, expires_at = self.token_service.create_verification_token(str(user.id), user.email)
        self.session.add(
            EmailVerificationToken(
                user_id=user.id,
                token_hash=self.token_service.hash_token(verification_token),
                expires_at=expires_at,
            )
        )
        await self.session.commit()
        await send_email(
            recipient=user.email,
            subject="Verify your account",
            body=f"Welcome {user.first_name}, your verification token is: {verification_token}",
        )

    async def verify_email(self, token: str) -> None:
        payload = self.token_service.decode_token(token, expected_type="verify")
        token_record = await self.session.scalar(
            select(EmailVerificationToken).where(
                EmailVerificationToken.token_hash == self.token_service.hash_token(token),
                EmailVerificationToken.user_id == payload.subject,
                EmailVerificationToken.used_at.is_(None),
            )
        )
        if token_record is None or token_record.expires_at <= datetime.now(UTC):
            raise AppError(401, "INVALID_VERIFICATION_TOKEN", "Verification token is invalid or expired.")

        user = await self.session.scalar(select(User).where(User.id == payload.subject))
        if user is None:
            raise AppError(404, "USER_NOT_FOUND", "User not found.")
        if user.is_verified:
            raise AppError(400, "ALREADY_VERIFIED", "Email is already verified.")

        user.is_verified = True
        token_record.used_at = datetime.now(UTC)
        await self.session.commit()
