"""
Authentication dependency — extracts and validates the JWT token from
the Authorization header, then loads the current user from the database.

SECURITY NOTES:
- All DB access uses parameterized ORM queries (filter_by / filter), NEVER raw SQL.
- Invalid or missing tokens result in a 401 Unauthorized response.
- The user object is injected into protected endpoints via FastAPI Depends.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models import User
from backend.security import decode_access_token

# Tells FastAPI to expect a Bearer token in the Authorization header.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Validate the JWT token and return the authenticated User.

    SECURITY: The token signature is verified by decode_access_token().
    The user is loaded via a parameterized ORM query — no raw SQL —
    preventing SQL Injection attacks through the token payload.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    username: str | None = payload.get("sub")
    if username is None:
        raise credentials_exception

    # SECURITY: Parameterized ORM query — SQLAlchemy escapes the input.
    # No string formatting or concatenation is used.
    user = db.query(User).filter(User.username == username).first()

    if user is None:
        raise credentials_exception

    return user
