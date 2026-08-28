"""
Security utilities: XSS sanitization, password hashing, JWT creation/verification,
and HTTP security headers middleware.

SECURITY NOTES:
- HTML entities are escaped via html.escape() to neutralize XSS payloads.
- Passwords hashed with bcrypt via passlib — never stored or compared as plaintext.
- JWT tokens are short-lived (30 min default) with HMAC-SHA256 signatures.
- Security headers middleware adds CSP, X-Frame-Options, X-Content-Type-Options,
  and Strict-Transport-Security to EVERY response.
"""

import html
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from backend.config import settings

# ---------------------------------------------------------------------------
# Password Hashing — bcrypt via passlib
# SECURITY: Plaintext passwords are NEVER stored or compared.
# ---------------------------------------------------------------------------

pwd_context = CryptContext(schemes=settings.BCRYPT_SCHEMES, deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against its bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ---------------------------------------------------------------------------
# JWT Token Management
# SECURITY: Tokens use HMAC-SHA256, short expiry, and carry user identity.
# ---------------------------------------------------------------------------

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Create a signed JWT access token.
    SECURITY: Expiry is enforced to limit token validity window.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict | None:
    """
    Decode and verify a JWT token.
    Returns the payload dict if valid, None otherwise.
    SECURITY: Signature is verified — forged tokens are rejected.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# ---------------------------------------------------------------------------
# XSS Sanitization
# SECURITY: All user-supplied strings stored in or rendered from the DB
# are HTML-escaped to prevent stored XSS attacks.
# ---------------------------------------------------------------------------

def sanitize_html(text: str) -> str:
    """
    Escape HTML entities in user input to prevent XSS injection.
    Converts <, >, &, ", ' to their safe HTML entity equivalents.
    """
    if not isinstance(text, str):
        return text
    return html.escape(text, quote=True)


def sanitize_url(url: str) -> str:
    """
    Sanitize a URL string for safe storage.
    Strips dangerous characters that could enable XSS via href attributes.
    """
    sanitized = sanitize_html(url)
    # SECURITY: Remove javascript: and data: protocol prefixes
    sanitized = sanitized.lower().replace("javascript:", "").replace("data:", "")
    return sanitized


# ---------------------------------------------------------------------------
# HTTP Security Headers Middleware
# SECURITY: Every response includes headers that prevent XSS, clickjacking,
# MIME sniffing attacks, and enforce HTTPS.
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects security-critical HTTP headers into every response.
    This is a defense-in-depth layer that complements application-level sanitization.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response: Response = await call_next(request)

        # SECURITY: Content-Security-Policy — blocks inline scripts, restricts sources
        response.headers["Content-Security-Policy"] = settings.CSP_HEADER

        # SECURITY: X-Frame-Options — prevents clickjacking (embedding in iframes)
        response.headers["X-Frame-Options"] = "DENY"

        # SECURITY: X-Content-Type-Options — prevents MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # SECURITY: Strict-Transport-Security — enforces HTTPS in browsers
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

        # SECURITY: Referrer-Policy — limits referrer leakage
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # SECURITY: Permissions-Policy — disables unnecessary browser features
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        # SECURITY: Remove server identification header
        if "server" in response.headers:
            del response.headers["server"]

        return response
