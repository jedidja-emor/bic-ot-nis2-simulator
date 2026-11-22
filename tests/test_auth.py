"""Authentication, token lifecycle and health endpoint tests."""
from __future__ import annotations

import time as _time

import jwt as pyjwt
import pytest

from app import auth as auth_module
from app.auth import create_access_token

from conftest import bearer, token_for, user_by_email

API = "/api/v1"


def test_health_ok(client):
    resp = client.get(f"{API}/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["database"] == "sqlite"


def test_login_success(client):
    resp = client.post(
        f"{API}/auth/login",
        json={"email": "admin@northgrid.io", "password": "NorthGrid123!"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert isinstance(body["access_token"], str) and body["access_token"]
    assert body["user"]["email"] == "admin@northgrid.io"
    assert body["user"]["tenant_id"] == 1


def test_login_wrong_password(client):
    resp = client.post(
        f"{API}/auth/login",
        json={"email": "admin@northgrid.io", "password": "DefinitelyWrong1!"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"]


def test_login_unknown_email(client):
    resp = client.post(
        f"{API}/auth/login",
        json={"email": "nobody@nowhere.io", "password": "Whatever123!"},
    )
    assert resp.status_code == 401


def test_auth_me_with_valid_token(client, token_northgrid_admin, tenant_ids):
    resp = client.get(f"{API}/auth/me", headers=bearer(token_northgrid_admin))
    assert resp.status_code == 200
    body = resp.json()
    user = body["user"]
    assert user["email"] == "admin@northgrid.io"
    assert user["tenant_id"] == tenant_ids["northgrid"]
    assert user["is_active"] is True
    assert user["is_vendor"] is False
    assert any(r["name"] == "tenant_admin" for r in body["roles"])


def test_auth_me_with_invalid_token(client):
    resp = client.get(f"{API}/auth/me", headers=bearer("not-a-valid-jwt-token"))
    assert resp.status_code == 401
    assert "detail" in resp.json()


def test_auth_me_with_expired_token(client, user_by_email):
    token = token_for(user_by_email, expires_minutes=-5)
    resp = client.get(f"{API}/auth/me", headers=bearer(token))
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


def test_auth_me_with_unknown_user_token(client):
    now = int(_time.time())
    payload = {
        "sub": "99999",
        "email": "ghost@beeincontrol.io",
        "tenant_id": None,
        "jti": "qa-ghost-token",
        "iat": now,
        "exp": now + 900,
    }
    token = pyjwt.encode(payload, auth_module.SECRET_KEY, algorithm=auth_module.ALGORITHM)
    resp = client.get(f"{API}/auth/me", headers=bearer(token))
    assert resp.status_code == 401


def test_auth_logout_revokes_token(client, token_northgrid_admin):
    resp = client.post(f"{API}/auth/logout", json={}, headers=bearer(token_northgrid_admin))
    assert resp.status_code == 200
    assert resp.json()["detail"] == "Logged out"

    resp = client.get(f"{API}/auth/me", headers=bearer(token_northgrid_admin))
    assert resp.status_code == 401


def test_protected_endpoint_requires_auth(client):
    resp = client.get(f"{API}/assets")
    assert resp.status_code == 401
    assert "detail" in resp.json()

def test_jwt_secret_uses_configured_value(monkeypatch):
    # F1 regression: an explicitly configured SECRET_KEY must be honoured.
    monkeypatch.setenv("SECRET_KEY", "qa-configured-secret-0123456789abcdef")
    assert auth_module._resolve_secret_key() == "qa-configured-secret-0123456789abcdef"


def test_jwt_secret_falls_back_to_ephemeral_random_key(monkeypatch):
    # F1 regression: when SECRET_KEY is unset/blank a fresh random key is used
    # instead of a known hardcoded default.
    monkeypatch.delenv("SECRET_KEY", raising=False)
    key = auth_module._resolve_secret_key()
    assert isinstance(key, str) and len(key) > 32
    assert "beeincontrol-dev-secret-change-me" not in key


def test_token_signed_with_removed_hardcoded_default_secret_is_rejected(client):
    # F1 regression: tokens signed with the retired hardcoded fallback secret
    # must no longer verify after the secure random/env fallback was introduced.
    now = int(_time.time())
    payload = {
        "sub": "1",
        "email": "admin@northgrid.io",
        "tenant_id": 1,
        "jti": "qa-retired-default-secret-token",
        "iat": now,
        "exp": now + 900,
    }
    token = pyjwt.encode(payload, "beeincontrol-dev-secret-change-me", algorithm="HS256")
    resp = client.get(f"{API}/auth/me", headers=bearer(token))
    assert resp.status_code == 401
