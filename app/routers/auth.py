from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_db_session
from app.middleware.auth import get_current_user
from app.models.user import User
from app.schemas.auth import AuthUserResponse, LoginRequest, LogoutRequest, MessageResponse, RefreshTokenRequest, RegisterRequest, TokenResponse
from app.schemas.extended_auth import ForgotPasswordRequest, ResetPasswordRequest, VerifyEmailRequest
from app.schemas.user import UserDetailResponse
from app.services.auth_service import AuthService
from app.services.user_service import UserService


router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=AuthUserResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, session: Annotated[AsyncSession, Depends(get_db_session)]):
    user = await AuthService(session).register(payload)
    return {"data": {"user": user, "message": "Registration successful. Verification email sent."}}


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, session: Annotated[AsyncSession, Depends(get_db_session)]):
    tokens = await AuthService(session).login(payload)
    return {"data": tokens.model_dump()}


@router.post("/logout", response_model=MessageResponse)
async def logout(payload: LogoutRequest, session: Annotated[AsyncSession, Depends(get_db_session)]):
    await AuthService(session).logout(payload.refresh_token)
    return {"data": {"message": "Logout successful."}}


@router.post("/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshTokenRequest, session: Annotated[AsyncSession, Depends(get_db_session)]):
    tokens = await AuthService(session).refresh(payload.refresh_token)
    return {"data": tokens.model_dump()}


@router.get("/me", response_model=UserDetailResponse)
async def me(current_user: Annotated[User, Depends(get_current_user)]):
    return {"data": UserService.serialize_user(current_user)}


@router.post("/verify-email", response_model=MessageResponse)
async def verify_email(payload: VerifyEmailRequest, session: Annotated[AsyncSession, Depends(get_db_session)]):
    await AuthService(session).verify_email(payload.token)
    return {"data": {"message": "Email verified successfully."}}


@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(payload: ForgotPasswordRequest, session: Annotated[AsyncSession, Depends(get_db_session)]):
    await AuthService(session).forgot_password(payload.email)
    return {"data": {"message": "If an account with that email exists, a reset link has been sent."}}


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(payload: ResetPasswordRequest, session: Annotated[AsyncSession, Depends(get_db_session)]):
    await AuthService(session).reset_password(payload.token, payload.new_password)
    return {"data": {"message": "Password reset successfully."}}
