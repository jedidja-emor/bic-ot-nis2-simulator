"""Shared pytest fixtures for the BeeInControl QA test suite.

Runs every test against a throwaway SQLite database (temp file) that is
re-created and re-seeded per test, with the FastAPI ``get_db`` dependency
overridden to use that database.  The FastAPI app under test is the real one
from ``backend/app`` (routers, RBAC, JIT, NIS2 timers, audit chain).
"""
from __future__ import annotations

import os
import pathlib
import sys
import tempfile
from typing import Iterator

# Make the backend package importable before the app modules are imported.
BACKEND_DIR = pathlib.Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Point the backend at a throwaway SQLite database before app modules load.
os.environ.setdefault("SECRET_KEY", "beeincontrol-qa-secret-key-0123456789abcdef")
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
os.environ.setdefault("BCRYPT_ROUNDS", "4")
os.environ.setdefault("CORS_ORIGINS", "*")
os.environ["DATABASE_URL"] = "sqlite:///" + str(
    (pathlib.Path(tempfile.gettempdir()) / "beeincontrol_pytest.db").as_posix()
)

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models  # noqa: F401  (register ORM models on Base.metadata)
from app.auth import create_access_token
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import Tenant, User
from app.seed import seed_database

Base.metadata.create_all(bind=engine)

API_PREFIX = "/api/v1"


def override_get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def get_user_by_email(email: str) -> User | None:
    db = SessionLocal()
    try:
        return db.query(User).filter(User.email == email).first()
    finally:
        db.close()


@pytest.fixture()
def user_by_email(email: str = "admin@northgrid.io") -> User | None:
    return get_user_by_email(email)


def token_for(user: User, expires_minutes: int | None = None) -> str:
    token, _payload = create_access_token(user, expires_minutes=expires_minutes)
    return token


@pytest.fixture(autouse=True)
def fresh_db() -> Iterator[None]:
    """Drop/create the schema and re-seed the simulator for every test."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_database(db)
    yield


@pytest.fixture()
def client(fresh_db: None):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def db_session() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


# ---------------------------------------------------------------------------
# Bearer tokens for the deterministic demo users created by the seed.
# ---------------------------------------------------------------------------
@pytest.fixture()
def token_platform() -> str:
    return token_for(get_user_by_email("platform@beeincontrol.io"))


@pytest.fixture()
def token_northgrid_admin() -> str:
    return token_for(get_user_by_email("admin@northgrid.io"))


@pytest.fixture()
def token_northgrid_engineer() -> str:
    return token_for(get_user_by_email("engineer@northgrid.io"))


@pytest.fixture()
def token_northgrid_officer() -> str:
    return token_for(get_user_by_email("officer@northgrid.io"))


@pytest.fixture()
def token_northgrid_viewer() -> str:
    return token_for(get_user_by_email("viewer@northgrid.io"))


@pytest.fixture()
def token_northgrid_vendor() -> str:
    return token_for(get_user_by_email("vendor@acme-ot.com"))


@pytest.fixture()
def token_aquaflow_admin() -> str:
    return token_for(get_user_by_email("admin@aquaflow.io"))


@pytest.fixture()
def token_transitrail_admin() -> str:
    return token_for(get_user_by_email("admin@transitrail.io"))


# ---------------------------------------------------------------------------
# Tenant identifiers of the three seeded tenants.
# ---------------------------------------------------------------------------
@pytest.fixture()
def tenant_ids() -> dict[str, int]:
    db = SessionLocal()
    try:
        rows = (
            db.query(Tenant)
            .filter(Tenant.slug.in_(["northgrid", "aquaflow", "transitrail"]))
            .all()
        )
        return {row.slug: int(row.id) for row in rows}
    finally:
        db.close()