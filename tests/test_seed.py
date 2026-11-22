"""System endpoints and deterministic seed data tests."""
from __future__ import annotations

from conftest import bearer

from app.models import Asset, Incident, JITAccessGrant, JITAccessRequest, Tenant, User

API = "/api/v1"


def test_health_ok(client):
    resp = client.get(f"{API}/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_seed_creates_three_tenants_with_users_and_assets(client, token_platform, db_session):
    tenants = db_session.query(Tenant).all()
    assert len(tenants) == 3
    slugs = sorted(t.slug for t in tenants)
    assert slugs == ["aquaflow", "northgrid", "transitrail"]

    users = db_session.query(User).all()
    assert len(users) == 12

    assets = db_session.query(Asset).all()
    assert len(assets) == 10

    northgrid = db_session.query(Tenant).filter(Tenant.slug == "northgrid").one()
    northgrid_assets = db_session.query(Asset).filter(Asset.tenant_id == northgrid.id).all()
    assert len(northgrid_assets) == 4
    assert {a.asset_tag for a in northgrid_assets} == {
        "PLC-001",
        "RTU-001",
        "HMI-001",
        "SENSOR-001",
    }


def test_seed_demo_credentials_login(client):
    resp = client.post(
        f"{API}/auth/login",
        json={"email": "vendor@acme-ot.com", "password": "Vendor123!"},
    )
    assert resp.status_code == 200
    assert resp.json()["access_token"]

def test_seed_endpoint_requires_authentication(client):
    # F2 regression: seeding must not be reachable without a valid token.
    resp = client.post(f"{API}/seed", json={})
    assert resp.status_code == 401
    assert "detail" in resp.json()


def test_seed_endpoint_rejected_for_tenant_user(client, token_northgrid_admin):
    # F2 regression: tenant admins must not be able to trigger seeding.
    resp = client.post(f"{API}/seed", json={}, headers=bearer(token_northgrid_admin))
    assert resp.status_code == 403


def test_seed_endpoint_platform_admin_no_credential_leak(client, token_platform):
    # F2 regression: platform-admin seeding must not return credentials or
    # password material in the response.
    resp = client.post(f"{API}/seed", json={}, headers=bearer(token_platform))
    assert resp.status_code == 200
    body = resp.json()
    assert "password" not in body
    assert "credentials" not in body
    assert "demo_credentials" not in body
    serialized = str(body)
    for secret in (
        "Platform123!",
        "NorthGrid123!",
        "AquaFlow123!",
        "TransitRail123!",
        "Vendor123!",
    ):
        assert secret not in serialized
