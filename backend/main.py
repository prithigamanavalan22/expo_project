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
import base64
import warnings
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Optional

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

from backend.analyzer import compute_report, lexical_risk, pick_verdict
from backend.ai_detector import analyze_forensic, auto_depth_ftr
from backend.auth import get_current_user
from backend.brand_checker import is_known_brand_domain, lookup_url
from backend.config import settings
from backend.database import Base, engine, get_db, init_db
from backend.logging_setup import get_logger, log_scan
from backend.models import BlacklistedDomain, ScannedURL, User
from backend.qr_detector import QRDecodeError, decode_qr_from_bytes, extract_urls
from backend.redirect_resolver import resolve_redirects
from backend.risk_factors import risk_factors
from backend.schemas import (
    DashboardResponse,
    QRScanRequest,
    QRScanResponse,
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
        get_logger().info("STARTUP  ML model loaded from %s", model_path)
    else:
        print(f"[!] WARNING: Model file not found at {model_path}")
        print("[!] Run 'python ml_model/train_model.py' first to train the model.")
        get_logger().warning("STARTUP  ML model file NOT found at %s", model_path)


# ---------------------------------------------------------------------------
# Application Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle — init DB and load ML model on boot."""
    init_db()
    load_ml_model()
    get_logger().info("STARTUP  PhishGuard backend is up and serving on http://127.0.0.1:8000")
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

    # =========================================================================
    #  REDIRECT UNWRAPPING
    #  If the URL hides the real destination behind one or more redirects
    #  (shorteners, open redirects, multi-hop phishing chains), resolve the
    #  chain FIRST and direct the ENTIRE analysis at the FINAL landing URL —
    #  the "base"/destination the user is actually taken to.
    # =========================================================================
    resolved = resolve_redirects(clean_url)
    redir_chain = resolved.get("redirect_chain") or []
    redir_count = resolved.get("redirect_count") or 0
    redir_error = resolved.get("error")

    # The analysis target = the final URL after unwrapping redirects.
    analysis_url = resolved.get("final_url") or clean_url

    # --- Check the domain blacklist (parameterized query) ---
    from urllib.parse import urlparse
    parsed = urlparse(analysis_url)
    hostname = parsed.hostname or ""

    blacklisted = db.query(BlacklistedDomain).filter(
        BlacklistedDomain.domain == hostname
    ).first()

    if blacklisted:
        # Blacklisted domain — immediate phishing verdict
        result = ScanResponse(
            id=0,
            url=analysis_url,
            prediction="phishing",
            confidence=1.0,
            scanned_at=datetime.now(timezone.utc),
            redirect_chain=redir_chain,
        )

        # Log the scan to the database
        log_entry = ScannedURL(
            user_id=current_user.id,
            url=analysis_url,
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
        features = extract_features(analysis_url)
        prediction_int = ml_pipeline.predict([features])[0]
        prediction_proba = ml_pipeline.predict_proba([features])[0]
        prediction = "phishing" if prediction_int == 1 else "safe"
        confidence = float(max(prediction_proba))
    else:
        # Fallback: heuristic-based detection when model isn't loaded
        confidence = 0.0
        risk_score = 0
        if "@" in analysis_url:
            risk_score += 1
        if not analysis_url.startswith("https://"):
            risk_score += 1
        if any(c.isdigit() for c in parsed.hostname or ""):
            risk_score += 1
        if analysis_url.count("-") > 3:
            risk_score += 1
        if len(analysis_url) > 75:
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
    #
    #  PROTECTION (false-positive prevention): We ONLY auto-blacklist when the
    #  high-confidence ML verdict is CORROBORATED by real structural phishing
    #  signals. Our ML model alone can misclassify clean domains (google.com,
    #  example.com) as phishing, so a high model confidence by itself is NOT
    #  enough to blacklist a domain for everyone. We also never blacklist a
    #  known legitimate brand domain.
    # =========================================================================
    lex_points, _lex_reasons = lexical_risk(analysis_url, hostname)
    if (
        prediction == "phishing"
        and confidence >= 0.95
        and hostname
        and not is_known_brand_domain(hostname)
        and lex_points >= 20            # corroborating structural red flags
    ):
        # SECURITY: Parameterized ORM query — check it's not already blacklisted
        already_blacklisted = db.query(BlacklistedDomain).filter(
            BlacklistedDomain.domain == hostname
        ).first()

        if already_blacklisted is None:
            # SECURITY: Insert only via ORM — never raw SQL
            new_blacklist = BlacklistedDomain(
                domain=hostname,
                reason=f"Auto-blacklisted by ML model (confidence {confidence:.2%}, lexical risk {lex_points}/60)",
            )
            db.add(new_blacklist)
            db.commit()
            print(f"[!] BLACKLISTED domain automatically: {hostname}")

    # =========================================================================
    #  AI AUTO-DETECTION + RISK SCORE + EXPLAINABILITY
    #  The ai_detector orchestrator fuses ML + lexical + sandbox content + the
    #  NEW visual brand-similarity (headless screenshot + image comparison).
    #
    #  The orchestrator auto-selects the analysis DEPTH based on the URL's risk
    #  profile (fast / deep / forensic). Even if the client only requested a
    #  fast scan, a high-risk URL automatically escalates to a forensic pass
    #  that includes the visual screenshot check — the "AI" auto-detection.
    # =========================================================================
    known_brand = bool(hostname) and is_known_brand_domain(hostname)

    forensic = analyze_forensic(
        url=analysis_url,
        hostname=hostname,
        ml_prediction=prediction,
        ml_confidence=confidence,
        requested_analysis=bool(getattr(body, "analysis", False)),
    )
    sandbox_findings = forensic.get("sandbox")
    visual_result = forensic.get("visual_brand")
    analysis_depth = forensic.get("depth", "fast")
    auto_escalated = bool(forensic.get("auto_escalated"))

    # Report the ORIGINAL multi-hop redirect chain (after unwrapping) as the
    # canonical redirect trail so the client sees the full journey, even though
    # the sandbox re-fetched the already-resolved final URL directly.
    if sandbox_findings is not None:
        sandbox_findings["redirect_chain"] = redir_chain
        sandbox_findings["redirect_count"] = redir_count
        sandbox_findings["redirected"] = bool(redir_count)

    report = compute_report(
        ml_prediction=prediction,
        ml_confidence=confidence,
        url=analysis_url,
        parsed_hostname=hostname,
        blacklisted=False,
        sandbox=sandbox_findings,
        known_brand=known_brand,
        visual=visual_result,
    )

    # =========================================================================
    #  VISUAL / EXTERNAL BRAND-REPUTATION CHECK
    #  Google Safe Browsing (when a key is configured) plus the built-in
    #  brand-lookalike heuristic. The standalone visual_brand result is already
    #  fused into the score above via compute_report.
    # =========================================================================
    brand_result = lookup_url(analysis_url)

    # If the brand check flags a lookalike or phishing, escalate the verdict.
    if brand_result["verdict"] in ("lookalike", "phishing"):
        if brand_result["verdict"] == "lookalike":
            # A lookalike is risky but may still be usable; raise to suspicious
            # unless it was already worse.
            if report.score < 50:
                report.score = max(report.score, 55)
                report.verdict = pick_verdict(report.score)
                report.reasons.append(brand_result["reason"])
        else:
            # External hard-phishing verdict -> escalate to phishing tier
            report.score = max(report.score, 85)
            report.verdict = "phishing"
            report.reasons.append(brand_result["reason"])

    final_verdict = report.verdict

    # =========================================================================
    #  STRUCTURED RISK FACTORS
    #  An exhaustive, machine-readable list of every individual risk found.
    # =========================================================================
    factors = risk_factors(
        url=analysis_url,
        hostname=hostname,
        sandbox=sandbox_findings,
        brand=brand_result,
        blacklisted=False,
        visual=visual_result,
    )

    # --- Log to database ---
    # SECURITY: analysis_url (sanitized / final landing URL) is stored, not raw input
    log_entry = ScannedURL(
        user_id=current_user.id,
        url=analysis_url,
        prediction=final_verdict,
        confidence=round(confidence, 4),
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    # --- File-based scan logging (persists even when server runs hidden) ---
    _client_ip = request.client.host if request.client else ""
    log_scan(url=analysis_url, prediction=final_verdict,
             risk_score=report.score, confidence=log_entry.confidence, ip=_client_ip)

    return ScanResponse(
        id=log_entry.id,
        url=analysis_url,
        prediction=final_verdict,
        confidence=log_entry.confidence,
        scanned_at=log_entry.scanned_at,
        risk_score=report.score,
        explanation=report.reasons,
        sandbox=sandbox_findings,
        redirect_chain=redir_chain,
        risk_factors=factors,
        brand=brand_result,
        visual_brand=visual_result,
        analysis_depth=analysis_depth,
        auto_escalated=auto_escalated,
    )


# ===========================================================================
#  QR CODE PHISHING SCAN ENDPOINT (JWT-Protected)
# ===========================================================================

@app.post(
    f"{settings.API_V1_PREFIX}/scan/qr",
    response_model=QRScanResponse,
    tags=["Scan"],
)
@limiter.limit(settings.RATE_LIMIT_SCAN)
async def scan_qr_code(
    request: Request,
    body: QRScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    """
    Upload a QR-code image (as base64 JSON) and scan the embedded URL(s).
    Detects 'quishing' — phishing delivered via QR codes.

    SECURITY CONTROLS:
    - JWT required: only authenticated users can scan QR codes.
    - Input validation: Pydantic caps base64 size (20MB max).
    - Image decoded in-memory with OpenCV; nothing is executed from the image.
    - Decoded URLs run through the SAME risk engine (risk score + explanation)
      as normal /scan requests.
    - Rate limiting: shared with the scan endpoint.
    """
    # --- Decode base64 image bytes ---
    try:
        image_bytes = base64.b64decode(body.image_base64, validate=True)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64 image data.",
        )

    # --- Decode QR code from image ---
    try:
        decoded = decode_qr_from_bytes(image_bytes)
    except QRDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    urls = extract_urls(decoded)

    if not urls:
        return QRScanResponse(
            decoded=decoded,
            urls_found=[],
            results=[],
            summary="QR code decoded, but it contained no http/https URL.",
            no_urls=True,
        )

    # --- Analyze each extracted URL through the shared risk engine ---
    results = []
    for u in urls:
        clean_u = sanitize_url(u)
        from urllib.parse import urlparse as _up
        u_host = _up(u).hostname or ""

        if ml_pipeline is not None:
            feats = extract_features(u)
            _int = ml_pipeline.predict([feats])[0]
            _proba = ml_pipeline.predict_proba([feats])[0]
            _pred = "phishing" if _int == 1 else "safe"
            _conf = float(max(_proba))
        else:
            _pred = "phishing" if "@" in u or _up(u).hostname and any(c.isdigit() for c in _up(u).hostname) else "safe"
            _conf = 0.5

        # Blacklist check (parameterized ORM)
        bl = db.query(BlacklistedDomain).filter(
            BlacklistedDomain.domain == u_host
        ).first()

        # Blacklisted domains return immediately — no heavy analysis needed.
        if bl is not None:
            results.append(ScanResponse(
                id=0,
                url=clean_u,
                prediction="phishing",
                confidence=1.0,
                scanned_at=datetime.now(timezone.utc),
                risk_score=95,
                explanation=["This domain is on the known phishing blacklist."],
                risk_factors=[{
                    "code": "blacklist", "name": "Known phishing blacklist hit",
                    "severity": "critical",
                    "description": "This domain is on the phishing blacklist.",
                }],
                brand=lookup_url(clean_u),
            ))
            continue

        # AI auto-detection: fuses ML + lexical + sandbox + visual brand check.
        forensic = analyze_forensic(
            url=clean_u,
            hostname=u_host,
            ml_prediction=_pred,
            ml_confidence=_conf,
            requested_analysis=bool(body.scan_url),
        )
        sb = forensic.get("sandbox")
        visual_result = forensic.get("visual_brand")
        analysis_depth = forensic.get("depth", "fast")
        auto_escalated = bool(forensic.get("auto_escalated"))

        # Brand-similarity / external reputation check
        brand_result = lookup_url(clean_u)

        report = compute_report(
            ml_prediction=_pred,
            ml_confidence=_conf,
            url=clean_u,
            parsed_hostname=u_host,
            blacklisted=False,
            sandbox=sb,
            known_brand=bool(u_host) and is_known_brand_domain(u_host),
            visual=visual_result,
        )

        # Escalate for external brand matches. NOTE: a hard external phishing
        # verdict escalates to the phishing tier (85+), while a merely-lookalike
        # verdict only bumps to suspicious — mirroring the /scan endpoint.
        if brand_result["verdict"] in ("lookalike", "phishing"):
            if brand_result["verdict"] == "phishing":
                report.score = max(report.score, 85)
                report.verdict = "phishing"
                report.reasons.append(brand_result["reason"])
            elif report.score < 50:
                report.score = max(report.score, 55)
                report.verdict = pick_verdict(report.score)
                report.reasons.append(brand_result["reason"])

        # Structured risk factors
        factors = risk_factors(
            url=clean_u,
            hostname=u_host,
            sandbox=sb,
            brand=brand_result,
            blacklisted=False,
            visual=visual_result,
        )

        log_qr = ScannedURL(
            user_id=current_user.id,
            url=clean_u,
            prediction=report.verdict,
            confidence=round(_conf, 4),
        )
        db.add(log_qr)
        db.commit()
        db.refresh(log_qr)

        results.append(ScanResponse(
            id=log_qr.id,
            url=clean_u,
            prediction=report.verdict,
            confidence=log_qr.confidence,
            scanned_at=log_qr.scanned_at,
            risk_score=report.score,
            explanation=report.reasons,
            sandbox=sb,
            redirect_chain=(sb or {}).get("redirect_chain", []),
            risk_factors=factors,
            brand=brand_result,
            visual_brand=visual_result,
            analysis_depth=analysis_depth,
            auto_escalated=auto_escalated,
        ))

    # --- Overall summary ---
    if any(r.prediction == "phishing" for r in results):
        summary = f"Phishing detected: {sum(1 for r in results if r.prediction == 'phishing')} of {len(results)} URL(s) found in the QR code are phishing."
    elif any(r.prediction == "suspicious" for r in results):
        summary = f"Suspicious: {sum(1 for r in results if r.prediction == 'suspicious')} of {len(results)} URL(s) in the QR code need caution."
    else:
        summary = f"All {len(results)} URL(s) in the QR code appear safe."

    return QRScanResponse(
        decoded=decoded,
        urls_found=urls,
        results=results,
        summary=summary,
        no_urls=False,
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
