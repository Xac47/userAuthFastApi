from fastapi import APIRouter, Depends, Form, HTTPException, Response, status

from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from typing import Annotated, List

from src.db.database import get_db
from src.core.config import settings
from src.users.auth import (
    authenticate_user,
    get_password_hash,
    get_user,
)
from src.users.dependencies import (
    get_current_user_for_refresh,
    get_current_verified_user,
    get_current_user,
)
from src.users.models import User
from src.users.shemas import FormDataAuth, TokenInfo, UserCreate, UserRead
from src.users.utils import (
    create_access_token,
    create_refresh_token,
    ACCESS_TOKEN_COOKIE_NAME,
    REFRESH_TOKEN_COOKIE_NAME,
    COOKIE_SAMESITE,
    COOKIE_SECURE,
    COOKIE_PATH,
)


router = APIRouter(prefix="/auth", tags=["auth & Пользователи"])


@router.get("/items/")
async def read_items(current_user: Annotated[UserRead, Depends(get_current_user)]):
    return {"email": current_user.email}


@router.get("/users/", response_model=List[UserRead])
async def users_list(db: AsyncSession = Depends(get_db)):
    stmt = select(User)
    result = await db.scalars(stmt)
    users = result.all()
    return users


@router.get("/users/me/", response_model=UserRead)
async def read_users_me(
    current_user: Annotated[UserRead, Depends(get_current_user)],
):
    return current_user


@router.post("/login/", response_model=TokenInfo, response_model_exclude_none=True)
async def login(
    form_data: Annotated[FormDataAuth, Form()],
    db: AsyncSession = Depends(get_db),
):
    user = await authenticate_user(form_data.email, form_data.password, db=db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    response = JSONResponse(
        content=TokenInfo(
            access_token=access_token, refresh_token=refresh_token
        ).model_dump()
    )
    # Set HttpOnly cookies
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE_NAME,
        value=access_token,
        httponly=True,
        samesite=COOKIE_SAMESITE,
        secure=COOKIE_SECURE,
        path=COOKIE_PATH,
        max_age=settings.auth_jwt.access_token_expire_minutes * 60,
    )
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        samesite=COOKIE_SAMESITE,
        secure=COOKIE_SECURE,
        path=COOKIE_PATH,
        max_age=settings.auth_jwt.refresh_token_expire_days * 24 * 60 * 60,
    )

    return response


@router.post("/sign-up/", status_code=status.HTTP_201_CREATED, response_model=UserRead)
async def create_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    if await get_user(user.email, db):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists"
        )

    hashed_password = get_password_hash(user.password)

    user_data = user.model_dump(exclude={"password", "password_2"})
    user_data["hashed_password"] = hashed_password

    new_user = User(**user_data)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return new_user


@router.post("/refresh/", response_model=TokenInfo, response_model_exclude_none=True)
async def auth_refresh_jwt(
    response: Response, user: UserRead = Depends(get_current_user_for_refresh)
):
    access_token = create_access_token(user)

    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE_NAME,
        value=access_token,
        httponly=True,
        samesite=COOKIE_SAMESITE,
        secure=COOKIE_SECURE,
        path=COOKIE_PATH,
        max_age=settings.auth_jwt.access_token_expire_minutes * 60,
    )
    return TokenInfo(access_token=access_token)


@router.post("/logout/")
async def logout(response: Response):
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return {"message": "successfully logged out"}