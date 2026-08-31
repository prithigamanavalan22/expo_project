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
    analysis: bool = Field(
        False,
        description="If true, also fetch and inspect the page content (URL sandbox).",
    )

    @field_validator("url")
    @classmethod
    def url_must_look_valid(cls, v: str) -> str:
        """Basic sanity check: must start with http:// or https://."""
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class QRScanRequest(BaseModel):
    """
    QR code phishing scan — the image bytes are sent as base64 in JSON.
    SECURITY: base64 text is validated/decoded server-side; the decoded
    payload is run through the exact same URL risk engine as normal scans.
    """
    image_base64: str = Field(..., min_length=16, max_length=20_000_000,
                              description="Base64-encoded image containing a QR code.")
    scan_url: bool = Field(True, description="Also run sandbox content analysis on decoded URL.")


class ScanResponse(BaseModel):
    """Scan result returned to the client."""
    id: int
    url: str
    prediction: str
    confidence: float
    scanned_at: datetime
    risk_score: int = Field(0, description="Risk score from 0 (safe) to 100 (phishing)")
    explanation: list[str] = Field(
        default_factory=list,
        description="Human-readable reasons why the URL was given this verdict.",
    )
    sandbox: Optional[dict] = Field(
        default=None,
        description="Optional content analysis of the fetched page.",
    )
    redirect_chain: list[dict] = Field(
        default_factory=list,
        description="Sequence of URLs/status codes the request followed (0+ hops).",
    )
    risk_factors: list[dict] = Field(
        default_factory=list,
        description="Structured risk factors (code/name/severity/description).",
    )
    brand: Optional[dict] = Field(
        default=None,
        description="External brand-similarity / reputation check result.",
    )
    visual_brand: Optional[dict] = Field(
        default=None,
        description="Visual brand-similarity result from screenshot + image comparison.",
    )
    analysis_depth: Optional[str] = Field(
        default=None,
        description="Auto-detection depth used: fast | deep | forensic.",
    )
    auto_escalated: Optional[bool] = Field(
        default=False,
        description="True when AI auto-escalated the analysis depth beyond what was requested.",
    )

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


# ---------------------------------------------------------------------------
# QR Scan Schemas
# ---------------------------------------------------------------------------

class QRScanResponse(BaseModel):
    """
    Result of scanning a QR-code image upload.
    Returns the decoded QR payload(s) plus the phishing verdict(s).
    """
    decoded: list[str] = Field(
        default_factory=list,
        description="Raw strings decoded from the QR code(s).",
    )
    urls_found: list[str] = Field(
        default_factory=list,
        description="URLs extracted from the QR payload.",
    )
    results: list[ScanResponse] = Field(
        default_factory=list,
        description="Risk analysis for each extracted URL (same format as /scan).",
    )
    summary: str = Field("", description="Overall verdict summary.")
    no_urls: bool = Field(
        False,
        description="True if the QR decoded but contained no http/https URL.",
    )
