from typing import Annotated
from fastapi import Depends, HTTPException, status, Request, Response

from sqlalchemy.ext.asyncio import AsyncSession

from src.db.database import get_db
from src.users.auth import get_user, oauth2_scheme
from src.users.schemas import UserRead
from src.users.utils import (
    decode_jwt,
    TOKEN_TYPE_FIELD,
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
    ACCESS_TOKEN_COOKIE_NAME,
    REFRESH_TOKEN_COOKIE_NAME,
    create_access_token,
    COOKIE_SAMESITE,
    COOKIE_SECURE,
    COOKIE_PATH,
)
from src.core.config import settings


async def validate_type_token(payload_token_type: str, token_type: str):
    """Validate that the payload token type matches the expected token type."""
    if payload_token_type != token_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid token type {payload_token_type!r} expected {token_type}",
        )


def credentials_exception():
    """Raise HTTP 401 exception for invalid credentials."""
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_user_by_token_sub(payload: dict, db: AsyncSession):
    """Get user from token payload subject (email)."""

    # Avoid strict Pydantic validation issues for 'exp'/'iat' types
    email = payload.get("email") or payload.get("sub")
    if not email:
        credentials_exception()

    user = await get_user(email, db)
    if user is None:
        credentials_exception()

    return user


async def get_current_user(
    request: Request,
    response: Response,
    token: Annotated[str | None, Depends(oauth2_scheme)],
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    """Get current user from access token."""

    # Try header first; if missing, fall back to cookie
    raw_token = token or request.cookies.get(ACCESS_TOKEN_COOKIE_NAME)
    if not raw_token:
        # No access token present → try refresh flow
        refresh_token = request.cookies.get(REFRESH_TOKEN_COOKIE_NAME)
        if not refresh_token:
            credentials_exception()
        refresh_payload = decode_jwt(refresh_token)
        await validate_type_token(
            refresh_payload.get(TOKEN_TYPE_FIELD), token_type=REFRESH_TOKEN_TYPE
        )
        user = await get_user_by_token_sub(refresh_payload, db)
        new_access = create_access_token(user)
        response.set_cookie(
            key=ACCESS_TOKEN_COOKIE_NAME,
            value=new_access,
            httponly=True,
            samesite=COOKIE_SAMESITE,
            secure=COOKIE_SECURE,
            path=COOKIE_PATH,
            max_age=settings.auth_jwt.access_token_expire_minutes * 60,
        )
        return user

    try:
        payload = decode_jwt(raw_token)
        payload_token_type = payload.get(TOKEN_TYPE_FIELD)
        await validate_type_token(payload_token_type, token_type=ACCESS_TOKEN_TYPE)
        user = await get_user_by_token_sub(payload, db)
        return user
    except HTTPException as exc:
        # If access token expired, try to refresh using refresh token cookie
        if (
            exc.status_code == status.HTTP_401_UNAUTHORIZED
            and exc.detail == "Token has expired"
        ):
            refresh_token = request.cookies.get(REFRESH_TOKEN_COOKIE_NAME)
            if not refresh_token:
                raise
            refresh_payload = decode_jwt(refresh_token)
            await validate_type_token(
                refresh_payload.get(TOKEN_TYPE_FIELD), token_type=REFRESH_TOKEN_TYPE
            )
            # We trust refresh token subject to issue new access token
            user = await get_user_by_token_sub(refresh_payload, db)
            new_access = create_access_token(user)
            response.set_cookie(
                key=ACCESS_TOKEN_COOKIE_NAME,
                value=new_access,
                httponly=True,
                samesite=COOKIE_SAMESITE,
                secure=COOKIE_SECURE,
                path=COOKIE_PATH,
                max_age=settings.auth_jwt.access_token_expire_minutes * 60,
            )
            return user
        raise


async def get_current_user_for_refresh(
    request: Request,
    token: Annotated[str | None, Depends(oauth2_scheme)],
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    """Get current user from refresh token."""

    raw_token = token
    if not raw_token:
        raw_token = request.cookies.get(REFRESH_TOKEN_COOKIE_NAME)
    if not raw_token:
        credentials_exception()

    payload = decode_jwt(raw_token)
    payload_token_type = payload.get(TOKEN_TYPE_FIELD)

    await validate_type_token(payload_token_type, token_type=REFRESH_TOKEN_TYPE)

    user = await get_user_by_token_sub(payload, db)

    return user


def ensure_active(user: UserRead):
    """Ensure user account is active."""
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user"
        )


async def get_current_active_user(
    current_user: Annotated[UserRead, Depends(get_current_user)],
):
    """Get current active user (must be authenticated and active)."""
    ensure_active(current_user)
    return current_user


def ensure_verified(user: UserRead):
    """Ensure user email is verified."""
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email is not verified",
            headers={"X-Error-Code": "user is not verified"},
        )


async def get_current_verified_user(
    current_user: Annotated[UserRead, Depends(get_current_active_user)],
):
    """Get current verified user (must be authenticated, active, and verified)."""
    ensure_verified(current_user)
    return current_user
