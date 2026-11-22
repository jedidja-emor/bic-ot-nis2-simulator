"""Database engine, session factory and declarative base."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
DATA_DIR = BACKEND_DIR / "data"

# Load backend/.env if present (does not override real environment variables).
load_dotenv(BACKEND_DIR / ".env")

DATA_DIR.mkdir(parents=True, exist_ok=True)

_default_db_path = (DATA_DIR / "beeincontrol.db").as_posix()
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{_default_db_path}")

# Relative sqlite URLs (e.g. sqlite:///./data/x.db) should be anchored to the
# backend directory rather than the process working directory.
if DATABASE_URL.startswith("sqlite:///") and not DATABASE_URL.startswith("sqlite:////"):
    raw_path = DATABASE_URL[len("sqlite:///") :]
    if raw_path == ":memory:":
        pass
    elif raw_path and not Path(raw_path).is_absolute():
        candidate = (BACKEND_DIR / raw_path).resolve()
        candidate.parent.mkdir(parents=True, exist_ok=True)
        DATABASE_URL = f"sqlite:///{candidate.as_posix()}"

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def get_db():
    """FastAPI dependency yielding a SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables. Safe to call repeatedly."""
    # Import models so they are registered on Base.metadata.
    from . import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
