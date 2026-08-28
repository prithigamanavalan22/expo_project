"""
Database setup using SQLAlchemy ORM.

SECURITY NOTE:
- ALL queries use parameterized ORM methods (add, filter, filter_by).
- Raw SQL strings or string interpolation are NEVER used, preventing SQL Injection.
- The engine is created with `echo=False` in production to avoid logging query params.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from backend.config import settings


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


engine = create_engine(
    settings.DATABASE_URL,
    connect_args=(
        {"check_same_thread": False}  # Required only for SQLite
        if "sqlite" in settings.DATABASE_URL
        else {}
    ),
    echo=False,  # SECURITY: Disable SQL logging in production
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Create all tables. Called once at application startup."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """
    FastAPI dependency that yields a DB session per request.
    Ensures sessions are always closed, preventing connection leaks.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
