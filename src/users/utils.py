from datetime import datetime, timedelta, timezone
import uuid
from fastapi import HTTPException, status
import jwt

from src.core.config import settings
from src.users.shemas import UserShema


TOKEN_TYPE_FIELD = "type"
ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"


def encode_jwt(
    payload: dict,
    private_key: str = settings.auth_jwt.private_key_path.read_text(),
    algorithm: str = settings.auth_jwt.algorithm,
    expire_minutes: int = settings.auth_jwt.access_token_expire_minutes,
    expire_timedelta: timedelta | None = None,
):
    to_encode = payload.copy()
    now = datetime.now(timezone.utc)
    if expire_timedelta:
        expire = now + expire_timedelta
    else:
        expire = now + timedelta(minutes=expire_minutes)
    to_encode.update(exp=expire, iat=now, jti=str(uuid.uuid4()))
    encoded = jwt.encode(to_encode, private_key, algorithm)

    return encoded


def decode_jwt(
    token: str | bytes,
    public_key: str = settings.auth_jwt.public_key_path.read_text(),
    algorithm: str = settings.auth_jwt.algorithm,
):
    try:
        payload = jwt.decode(token, public_key, algorithms=[algorithm])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def create_jwt(
    token_type: str,
    payload: dict,
    expire_minutes: int = settings.auth_jwt.access_token_expire_minutes,
    expire_timedeltra: timedelta | None = None,
) -> str:
    jwt_payload = {TOKEN_TYPE_FIELD: token_type}
    jwt_payload.update(payload)
    return encode_jwt(
        payload=jwt_payload,
        expire_minutes=expire_minutes,
        expire_timedelta=expire_timedeltra,
    )


def create_access_token(user: UserShema) -> str:
    toket_data = {"sub": user.email, "email": user.email}

    return create_jwt(
        token_type=ACCESS_TOKEN_TYPE,
        payload=toket_data,
        expire_minutes=settings.auth_jwt.access_token_expire_minutes,
    )


def create_refresh_token(user: UserShema) -> str:
    token_data = {"sub": user.email, "email": user.email}
    return create_jwt(
        token_type=REFRESH_TOKEN_TYPE,
        payload=token_data,
        expire_timedeltra=timedelta(days=settings.auth_jwt.refresh_token_expire_days),
    )
