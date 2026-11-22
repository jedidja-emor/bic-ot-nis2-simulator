"""Seed and health/system endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..database import DATABASE_URL, get_db
from ..deps import get_current_user, is_platform_admin
from ..models import User
from ..seed import seed_database

router = APIRouter(tags=["system"])


@router.post("/seed")
def seed(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not is_platform_admin(db, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only platform admins may seed the database",
        )
    return seed_database(db)


@router.get("/health")
def health(db: Session = Depends(get_db)):
    db_version = None
    db_ok = True
    try:
        if DATABASE_URL.startswith("sqlite"):
            db_version = db.execute(text("SELECT sqlite_version()")).scalar()
        else:
            db_version = db.execute(text("SELECT version()")).scalar()
    except Exception as exc:  # pragma: no cover - defensive health probe
        db_ok = False
        db_version = str(exc)

    return {
        "status": "ok" if db_ok else "degraded",
        "database": "sqlite" if DATABASE_URL.startswith("sqlite") else "other",
        "database_version": db_version,
    }
