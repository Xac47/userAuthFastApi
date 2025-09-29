from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.users.models import User


http_bearer = HTTPBearer(auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def get_user(email: EmailStr, db: AsyncSession) -> User | None:
    """Fetch a user by email or return None if not found."""
    query = select(User).where(User.email == email)
    result = await db.execute(query)
    return result.scalar_one_or_none()


def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    """Verify a plain password against a hashed password using bcrypt."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password) -> bytes:
    """Hash a password using bcrypt and return the hash."""
    return pwd_context.hash(password)


async def authenticate_user(email: str, password: str, db: AsyncSession):
    """Authenticate a user by email and password; return user or False."""
    user = await get_user(email=email, db=db)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user"
        )

    return user
