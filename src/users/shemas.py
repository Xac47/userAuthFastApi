from datetime import timedelta
from datetime import datetime
from typing import Annotated, Any
from annotated_types import MaxLen, MinLen
from pydantic import BaseModel, ConfigDict, EmailStr, field_validator, constr, Field

FULL_NAME = Annotated[
    constr(min_length=6, max_length=50), Field(description="First_name Last_name")
]
PASSWORD = Annotated[constr(min_length=8, max_length=32), Field(description="password")]


class UserShema(BaseModel):
    id: int
    email: EmailStr | None = None
    hashed_password: bytes | str
    is_active: bool = True
    is_verified: bool = True
    full_name: FULL_NAME | None = None
    avatar_url: str | None = None
    last_login_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class UserRead(BaseModel):
    id: int
    email: EmailStr | None = None
    is_active: bool = True
    is_verified: bool = True
    full_name: FULL_NAME | None = None
    avatar_url: str | None = None
    last_login_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class UserCreate(BaseModel):
    # username: Annotated[str, MinLen(8), MaxLen(20)]
    full_name: FULL_NAME
    email: EmailStr
    password: PASSWORD
    password_2: PASSWORD

    @field_validator("password_2")
    def password_match(cls, v, values):
        if "password" in values.data and v != values.data["password"]:
            raise ValueError("Passwords do not match")
        return v


class UserAuth(BaseModel):
    email: str
    hashed_password: str
    is_active: bool | None
    is_verified: bool | None


class TokenInfo(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"


class TokenData(BaseModel):
    """
    token data:
        {'sub': str, 'email': email, 'exp': timedeltra, 'iat': timedeltra}
    """

    sub: str
    email: EmailStr | None = None
    exp: timedelta
    iat: timedelta


class FormDataAuth(BaseModel):
    email: EmailStr
    password: str
