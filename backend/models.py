"""
SQLAlchemy ORM Models — User, ScannedURL, BlacklistedDomain.

SECURITY NOTES:
- Passwords are stored as bcrypt hashes, NEVER plaintext.
- All relationships use foreign keys enforced at the DB level.
- No computed raw SQL — all access goes through ORM to prevent SQL Injection.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base


class User(Base):
    """
    Registered user account.
    SECURITY: password_hash is a bcrypt hash — never store plaintext passwords.
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationship to scan history
    scans: Mapped[list["ScannedURL"]] = relationship(
        "ScannedURL", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}')>"


class ScannedURL(Base):
    """
    Audit log of every URL scanned by users.
    SECURITY: Input/output are sanitized before storage to prevent stored XSS.
    """
    __tablename__ = "scanned_urls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    prediction: Mapped[str] = mapped_column(String(32), nullable=False)  # "safe" or "phishing"
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    user: Mapped["User"] = relationship("User", back_populates="scans")

    def __repr__(self):
        return f"<ScannedURL(id={self.id}, prediction='{self.prediction}')>"


class BlacklistedDomain(Base):
    """
    Admin-maintained blocklist of known phishing domains.
    SECURITY: Only trusted admin users should modify this table via internal tooling.
    """
    __tablename__ = "blacklisted_domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(256), unique=True, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=True)
    added_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def __repr__(self):
        return f"<BlacklistedDomain(domain='{self.domain}')>"


class WhitelistedDomain(Base):
    """
    Admin-confirmed safe domains.
    A whitelisted domain is NEVER instant-blocked by the blacklist and is
    excluded from future auto-blacklisting. It also neutralizes a lone
    high-confidence ML "phishing" verdict (treated like a known brand) so a
    legitimate new site can never be permanently branded PHISHING by noise.
    """
    __tablename__ = "whitelisted_domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(256), unique=True, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=True)
    added_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    def __repr__(self):
        return f"<WhitelistedDomain(domain='{self.domain}')>"
