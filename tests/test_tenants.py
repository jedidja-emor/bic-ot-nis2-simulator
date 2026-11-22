"""Tenant management, seeding and cross-tenant access isolation tests."""
from __future__ import annotations

from conftest import bearer

API = "/api/v1"


def test_health_ok(client):
    resp = client.get(f"{API}/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["database"] == "sqlite"


def test_seed_creates_three_tenants(client, token_platform, tenant_ids):
    resp = client.get(f"{API}/tenants", headers=bearer(token_platform))
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 3
    slugs = {t["slug"] for t in body}
    assert slugs == {"northgrid", "aquaflow", "transitrail"}
    sectors = {t["sector"] for t in body}
    assert sectors == {"energy", "water", "transport"}


def test_tenant_user_lists_only_own_tenant(client, token_northgrid_admin, tenant_ids):
    resp = client.get(f"{API}/tenants", headers=bearer(token_northgrid_admin))
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["id"] == tenant_ids["northgrid"]
    assert body[0]["slug"] == "northgrid"


def test_platform_admin_lists_all_tenants(client, token_platform):
    resp = client.get(f"{API}/tenants", headers=bearer(token_platform))
    assert resp.status_code == 200
    assert len(resp.json()) == 3


def test_tenant_user_cannot_create_tenant(client, token_northgrid_admin):
    resp = client.post(
        f"{API}/tenants",
        json={"name": "Rogue Plant", "slug": "rogueplant", "sector": "energy", "is_active": True},
        headers=bearer(token_northgrid_admin),
    )
    assert resp.status_code == 403


def test_platform_admin_creates_and_conflicts_tenant(client, token_platform):
    payload = {
        "name": "TestPlant GmbH",
        "slug": "testplant",
        "sector": "water",
        "is_active": True,
    }
    resp = client.post(f"{API}/tenants", json=payload, headers=bearer(token_platform))
    assert resp.status_code == 201
    tenant = resp.json()
    assert tenant["slug"] == "testplant"
    assert tenant["is_active"] is True

    got = client.get(f"{API}/tenants/{tenant['id']}", headers=bearer(token_platform))
    assert got.status_code == 200
    assert got.json()["id"] == tenant["id"]

    dup = client.post(f"{API}/tenants", json=payload, headers=bearer(token_platform))
    assert dup.status_code == 409


def test_tenant_user_cannot_access_other_tenant(client, token_northgrid_admin, tenant_ids):
    resp = client.get(f"{API}/tenants/{tenant_ids['aquaflow']}", headers=bearer(token_northgrid_admin))
    assert resp.status_code == 403
