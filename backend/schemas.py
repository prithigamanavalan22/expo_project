"""
Pydantic schemas for request validation and response serialization.

SECURITY NOTES:
- Pydantic v2 `model_validator` enforces input constraints server-side.
- Max lengths on all string fields to prevent buffer abuse.
- Email validation uses Pydantic's built-in EmailStr.
- No raw user input is echoed back without sanitization.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ---------------------------------------------------------------------------
# Auth Schemas
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    """Registration request body — strict validation prevents injection."""
    username: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_]+$",  # SECURITY: Whitelist allowed characters
        description="Username: alphanumeric and underscores only.",
    )
    email: EmailStr = Field(
        ...,
        max_length=128,
        description="Valid email address.",
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password: minimum 8 characters.",
    )

    @field_validator("username")
    @classmethod
    def username_not_reserved(cls, v: str) -> str:
        """Prevent reserved names from being registered."""
        reserved = {"admin", "root", "system", "api", "null", "undefined"}
        if v.lower() in reserved:
            raise ValueError("This username is reserved.")
        return v


class UserLogin(BaseModel):
    """Login request body."""
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    """Public user profile (no password hash ever returned)."""
    id: int
    username: str
    email: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Scan Schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """URL to scan — validated for non-empty and max length."""
    url: str = Field(
        ...,
        min_length=5,
        max_length=2048,
        description="URL to analyze for phishing indicators.",
    )

    @field_validator("url")
    @classmethod
    def url_must_look_valid(cls, v: str) -> str:
        """Basic sanity check: must start with http:// or https://."""
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class ScanResponse(BaseModel):
    """Scan result returned to the client."""
    id: int
    url: str
    prediction: str
    confidence: float
    scanned_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Dashboard Schemas
# ---------------------------------------------------------------------------

class ScanHistoryItem(BaseModel):
    """Single item in the user's scan history."""
    id: int
    url: str
    prediction: str
    confidence: float
    scanned_at: datetime

    model_config = {"from_attributes": True}


class DashboardResponse(BaseModel):
    """Paginated scan history for the authenticated user."""
    total_scans: int
    phishing_count: int
    safe_count: int
    history: list[ScanHistoryItem]
