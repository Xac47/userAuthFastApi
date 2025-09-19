from fastapi import APIRouter, Depends, Form, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from typing import Annotated, List

from src.db.database import get_db
from src.users.auth import (
    authenticate_user,
    get_password_hash,
    get_user,
    oauth2_scheme,
    http_bearer,
)
from src.users.dependencies import (
    get_current_active_user,
    get_current_user_for_refresh,
    get_current_verified_user,
)
from src.users.models import User
from src.users.shemas import FormDataAuth, TokenInfo, UserCreate, UserRead
from src.users.utils import create_access_token, create_refresh_token


router = APIRouter(
    prefix="/auth", tags=["auth & Пользователи"], dependencies=[Depends(http_bearer)]
)


@router.get("/items")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}


@router.get("/users", response_model=List[UserRead])
async def users_list(db: AsyncSession = Depends(get_db)):
    stmt = select(User)
    result = await db.scalars(stmt)
    users = result.all()
    return users


@router.get("/users/me", response_model=UserRead)
async def read_users_me(
    current_user: Annotated[UserRead, Depends(get_current_verified_user)],
):
    return current_user


@router.post("/login", response_model=TokenInfo, response_model_exclude_none=True)
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

    return TokenInfo(access_token=access_token, refresh_token=refresh_token)


@router.post("/sign-up", status_code=status.HTTP_201_CREATED, response_model=UserRead)
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
async def auth_refresh_jwt(user: UserRead = Depends(get_current_user_for_refresh)):
    access_token = create_access_token(user)

    return TokenInfo(access_token=access_token)
