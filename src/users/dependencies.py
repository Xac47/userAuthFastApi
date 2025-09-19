from typing import Annotated
from fastapi import Depends, HTTPException, status
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.database import get_db
from src.users.auth import get_user, oauth2_scheme
from src.users.shemas import TokenData, UserRead
from src.users.utils import (
    decode_jwt,
    TOKEN_TYPE_FIELD,
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
)


async def validate_type_token(payload_token_type: str, token_type: str):
    if payload_token_type != token_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid token type {payload_token_type!r} expected {token_type}",
        )


def credentials_exception():
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_user_by_token_sub(payload: dict, db: AsyncSession):

    try:
        token_data = TokenData(**payload)
    except ValidationError:
        credentials_exception()

    user = await get_user(token_data.email, db)
    if user is None:
        credentials_exception()

    return user


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)], db: AsyncSession = Depends(get_db)
) -> UserRead:

    payload = decode_jwt(token)
    payload_token_type = payload.get(TOKEN_TYPE_FIELD)

    await validate_type_token(payload_token_type, token_type=ACCESS_TOKEN_TYPE)

    user = await get_user_by_token_sub(payload, db)

    return user


async def get_current_user_for_refresh(
    token: Annotated[str, Depends(oauth2_scheme)], db: AsyncSession = Depends(get_db)
) -> UserRead:

    payload = decode_jwt(token)
    payload_token_type = payload.get(TOKEN_TYPE_FIELD)

    await validate_type_token(payload_token_type, token_type=REFRESH_TOKEN_TYPE)

    user = await get_user_by_token_sub(payload, db)

    return user


def ensure_active(user: UserRead):
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user"
        )


async def get_current_active_user(
    current_user: Annotated[UserRead, Depends(get_current_user)],
):
    ensure_active(current_user)
    return current_user


def ensure_verified(user: UserRead):
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email is not verified",
            headers={"X-Error-Code": "user is not verified"},
        )


async def get_current_verified_user(
    current_user: Annotated[UserRead, Depends(get_current_active_user)],
):
    ensure_verified(current_user)
    return current_user
