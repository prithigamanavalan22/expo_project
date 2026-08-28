"""
Application configuration — environment-driven, no hardcoded secrets in code.
Loads from environment variables with safe defaults for local development.
"""

import os
from pathlib import Path


class Settings:
    """Central configuration class. All secrets MUST come from env vars in production."""

    PROJECT_NAME: str = "PhishGuard API"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"

    # --- Database ---
    # SECURITY: In production, use a real PostgreSQL/MySQL URI.
    # SQLite is used here for zero-config local dev only.
    BASE_DIR: str = str(Path(__file__).resolve().parent)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'phishguard.db')}",
    )

    # --- JWT Authentication ---
    # SECURITY: In production, load SECRET_KEY from a secrets manager (Vault, AWS SM).
    SECRET_KEY: str = os.getenv("SECRET_KEY", "CHANGE-ME-IN-PRODUCTION-USE-RANDOM-64-CHAR-STRING")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # --- Password Hashing ---
    # bcrypt via passlib — never store plaintext passwords.
    BCRYPT_SCHEMES: list[str] = ["bcrypt"]

    # --- Rate Limiting ---
    # SECURITY: 30 scan requests per minute per IP to prevent abuse / DoS.
    RATE_LIMIT_SCAN: str = "30/minute"
    RATE_LIMIT_AUTH: str = "10/minute"

    # --- ML Model ---
    ML_MODEL_PATH: str = os.path.join(
        Path(__file__).resolve().parent.parent, "ml_model", "model", "phishing_model.pkl"
    )

    # --- Security Headers ---
    # SECURITY: Strict CSP to prevent XSS injection via inline scripts.
    CSP_HEADER: str = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )

    # --- CORS (allow all origins for local dev + Chrome extension) ---
    # SECURITY: The extension service worker sends requests from chrome-extension:// origin
    # which cannot be predicted. For local-only API this is safe.
    CORS_ORIGINS: list[str] = ["*"]


settings = Settings()
