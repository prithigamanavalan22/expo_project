"""
PhishGuard API — FastAPI Application Entry Point.

Endpoints:
  POST /api/v1/auth/register  — Register a new user account
  POST /api/v1/auth/login     — Authenticate and receive a JWT token
  POST /api/v1/scan           — Scan a URL for phishing (JWT-protected)
  GET  /api/v1/dashboard/history — Retrieve user's scan history (JWT-protected)

SECURITY CONTROLS IMPLEMENTED:
  - SQL Injection:  ALL DB access uses SQLAlchemy ORM parameterized queries.
  - XSS:            All output is HTML-escaped; security headers enforced on every response.
  - Broken Auth:    bcrypt password hashing + JWT with short-lived tokens.
  - API Logic Flaws: Rate limiting via slowapi; Pydantic input validation on all endpoints.
"""

import os
import sys
import warnings
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated

import joblib
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Path setup so we can import ml_model.feature_extractor
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml_model.feature_extractor import extract_features

from backend.auth import get_current_user
from backend.config import settings
from backend.database import Base, engine, get_db, init_db
from backend.models import BlacklistedDomain, ScannedURL, User
from backend.schemas import (
    DashboardResponse,
    ScanHistoryItem,
    ScanRequest,
    ScanResponse,
    TokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)
from backend.security import (
    SecurityHeadersMiddleware,
    create_access_token,
    hash_password,
    sanitize_html,
    sanitize_url,
    verify_password,
)

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Rate Limiting via slowapi
# SECURITY: Prevents brute-force attacks on auth endpoints and API abuse.
#            30 scans/min per IP, 10 auth requests/min per IP.
# ---------------------------------------------------------------------------
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

# ---------------------------------------------------------------------------
# ML Model Loading
# ---------------------------------------------------------------------------
ml_pipeline = None


def load_ml_model():
    """Load the trained Random Forest pipeline from disk."""
    global ml_pipeline
    model_path = settings.ML_MODEL_PATH
    if os.path.exists(model_path):
        ml_pipeline = joblib.load(model_path)
        print(f"[+] ML model loaded from {model_path}")
    else:
        print(f"[!] WARNING: Model file not found at {model_path}")
        print("[!] Run 'python ml_model/train_model.py' first to train the model.")


# ---------------------------------------------------------------------------
# Application Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle — init DB and load ML model on boot."""
    init_db()
    load_ml_model()
    yield
    # Shutdown: cleanup resources if needed


# ---------------------------------------------------------------------------
# FastAPI App Initialization
# ---------------------------------------------------------------------------
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
)

# Attach rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# SECURITY: CORS locked down — only the local extension/server can call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# SECURITY: Injects X-Frame-Options, CSP, X-Content-Type-Options, HSTS on every response.
app.add_middleware(SecurityHeadersMiddleware)


# ===========================================================================
#  AUTH ENDPOINTS
# ===========================================================================

@app.post(
    f"{settings.API_V1_PREFIX}/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
)
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def register(request: Request, body: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user account.

    SECURITY:
    - Input is validated by Pydantic (regex, min/max length, email format).
    - Password is bcrypt-hashed BEFORE storage — plaintext is NEVER persisted.
    - Duplicate username/email checks use parameterized ORM queries.
    """
    # SECURITY: Parameterized query — no string concatenation
    existing_user = db.query(User).filter(
        (User.username == body.username) | (User.email == body.email)
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered.",
        )

    new_user = User(
        username=sanitize_html(body.username),
        email=sanitize_html(body.email),
        password_hash=hash_password(body.password),
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@app.post(
    f"{settings.API_V1_PREFIX}/auth/login",
    response_model=TokenResponse,
    tags=["Authentication"],
)
@limiter.limit(settings.RATE_LIMIT_AUTH)
async def login(request: Request, body: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticate a user and return a JWT access token.

    SECURITY:
    - Password is verified against bcrypt hash — not stored in JWT payload.
    - Generic error messages prevent username enumeration.
    - Rate-limited to 10 requests/minute per IP to thwart brute-force.
    """
    # SECURITY: Parameterized query
    user = db.query(User).filter(User.username == body.username).first()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    access_token = create_access_token(data={"sub": user.username})
    return TokenResponse(access_token=access_token)


# ===========================================================================
#  SCAN ENDPOINT (JWT-Protected)
# ===========================================================================

@app.post(
    f"{settings.API_V1_PREFIX}/scan",
    response_model=ScanResponse,
    tags=["Scan"],
)
@limiter.limit(settings.RATE_LIMIT_SCAN)
async def scan_url(
    request: Request,
    body: ScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    """
    Scan a URL for phishing indicators.

    SECURITY CONTROLS:
    - JWT Authentication: Only logged-in users can scan.
    - Input Validation: Pydantic enforces URL format, max length, protocol prefix.
    - XSS Prevention: URL is sanitized before storage (html.escape + protocol stripping).
    - SQL Injection: All DB operations use parameterized ORM queries.
    - Rate Limiting: 30 scans/minute per IP prevents API abuse.
    - Blacklist Check: Domain is checked against known phishing blacklist.
    - Model Fallback: If ML model isn't loaded, returns a safe diagnostic response.
    """
    url = body.url.strip()

    # SECURITY: Sanitize URL before any processing or storage
    clean_url = sanitize_url(url)

    # --- Check the domain blacklist (parameterized query) ---
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    blacklisted = db.query(BlacklistedDomain).filter(
        BlacklistedDomain.domain == hostname
    ).first()

    if blacklisted:
        # Blacklisted domain — immediate phishing verdict
        result = ScanResponse(
            id=0,
            url=clean_url,
            prediction="phishing",
            confidence=1.0,
            scanned_at=datetime.now(timezone.utc),
        )

        # Log the scan to the database
        log_entry = ScannedURL(
            user_id=current_user.id,
            url=clean_url,
            prediction="phishing",
            confidence=1.0,
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)

        result.id = log_entry.id
        result.scanned_at = log_entry.scanned_at
        return result

    # --- ML Model Prediction ---
    if ml_pipeline is not None:
        features = extract_features(url)
        prediction_int = ml_pipeline.predict([features])[0]
        prediction_proba = ml_pipeline.predict_proba([features])[0]
        prediction = "phishing" if prediction_int == 1 else "safe"
        confidence = float(max(prediction_proba))
    else:
        # Fallback: heuristic-based detection when model isn't loaded
        confidence = 0.0
        risk_score = 0
        if "@" in url:
            risk_score += 1
        if not url.startswith("https://"):
            risk_score += 1
        if any(c.isdigit() for c in parsed.hostname or ""):
            risk_score += 1
        if url.count("-") > 3:
            risk_score += 1
        if len(url) > 75:
            risk_score += 1
        prediction = "phishing" if risk_score >= 3 else "safe"
        confidence = min(risk_score / 5.0, 0.95)

    # =========================================================================
    #  AUTO-BLACKLIST HIGH-CONFIDENCE PHISHING DOMAINS
    #  SECURITY: When the model flags a URL as phishing with confidence >= 0.95,
    #  this domain is automatically added to the shared BlacklistedDomain table.
    #  This protects ALL users: any future scan of the same domain is instantly
    #  blocked before even reaching the ML model.
    #  The unique constraint on `domain` ensures each domain is added only once.
    # =========================================================================
    if prediction == "phishing" and confidence >= 0.95 and hostname:
        # SECURITY: Parameterized ORM query — check it's not already blacklisted
        already_blacklisted = db.query(BlacklistedDomain).filter(
            BlacklistedDomain.domain == hostname
        ).first()

        if already_blacklisted is None:
            # SECURITY: Insert only via ORM — never raw SQL
            new_blacklist = BlacklistedDomain(
                domain=hostname,
                reason=f"Auto-blacklisted by ML model (confidence {confidence:.2%})",
            )
            db.add(new_blacklist)
            db.commit()
            print(f"[!] BLACKLISTED domain automatically: {hostname}")

    # --- Log to database ---
    # SECURITY: clean_url (sanitized) is stored, not raw user input
    log_entry = ScannedURL(
        user_id=current_user.id,
        url=clean_url,
        prediction=prediction,
        confidence=round(confidence, 4),
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    return ScanResponse(
        id=log_entry.id,
        url=clean_url,
        prediction=log_entry.prediction,
        confidence=log_entry.confidence,
        scanned_at=log_entry.scanned_at,
    )


# ===========================================================================
#  DASHBOARD ENDPOINT (JWT-Protected)
# ===========================================================================

@app.get(
    f"{settings.API_V1_PREFIX}/dashboard/history",
    response_model=DashboardResponse,
    tags=["Dashboard"],
)
@limiter.limit(settings.RATE_LIMIT_SCAN)
async def get_dashboard_history(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    """
    Retrieve the authenticated user's scan history with summary statistics.

    SECURITY:
    - JWT required — users can ONLY see their own history (filtered by user_id).
    - All queries are parameterized ORM — no SQL Injection risk.
    - Output URLs are sanitized to prevent stored XSS when rendered in the dashboard.
    """
    # SECURITY: Filtered by user_id — users cannot access others' data
    user_scans = (
        db.query(ScannedURL)
        .filter(ScannedURL.user_id == current_user.id)
        .order_by(ScannedURL.scanned_at.desc())
        .all()
    )

    total = len(user_scans)
    phishing = sum(1 for s in user_scans if s.prediction == "phishing")
    safe = total - phishing

    history = [
        ScanHistoryItem(
            id=scan.id,
            url=sanitize_html(scan.url),  # SECURITY: XSS prevention on output
            prediction=scan.prediction,
            confidence=scan.confidence,
            scanned_at=scan.scanned_at,
        )
        for scan in user_scans
    ]

    return DashboardResponse(
        total_scans=total,
        phishing_count=phishing,
        safe_count=safe,
        history=history,
    )


# ===========================================================================
#  HEALTH CHECK
# ===========================================================================

@app.get("/health", tags=["Health"])
async def health_check():
    """Simple liveness probe."""
    return {"status": "healthy", "model_loaded": ml_pipeline is not None}


# ===========================================================================
#  ENTRY POINT
# ===========================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
