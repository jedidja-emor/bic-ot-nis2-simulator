"""Tenant-scoped RBAC, permission matrix and cross-tenant access tests."""
from __future__ import annotations

from conftest import bearer

API = "/api/v1"


def test_tenant_admin_permission_union(client, token_northgrid_admin):
    resp = client.get(f"{API}/auth/me", headers=bearer(token_northgrid_admin))
    assert resp.status_code == 200
    codes = resp.json()["permission_codes"]
    for required in [
        "asset:read",
        "asset:write",
        "asset:jit_access",
        "incident:read",
        "incident:declare",
        "incident:early_warning",
        "incident:notify",
        "jit:request",
        "jit:approve",
        "jit:read",
        "audit:read",
        "user:manage",
    ]:
        assert required in codes, f"tenant_admin missing permission {required}"


def test_viewer_cannot_write_assets_or_approve_jit(client, token_northgrid_viewer, token_northgrid_admin):
    # viewer holds only read-side permissions for assets/incidents/audit.
    resp = client.post(
        f"{API}/assets",
        json={
            "tenant_id": 1,
            "asset_tag": "SENSOR-999",
            "name": "Rogue Sensor",
            "type": "SENSOR",
            "site": "Nowhere",
            "status": "online",
        },
        headers=bearer(token_northgrid_viewer),
    )
    assert resp.status_code == 403

    # admin creates a JIT request, viewer (no jit:approve) must be rejected.
    created = client.post(
        f"{API}/jit/requests",
        json={
            "tenant_id": 1,
            "asset_id": 1,
            "reason": "Field diagnostic access",
            "requested_permissions": "asset:jit_access",
            "requested_until": "2030-01-01T00:00:00Z",
        },
        headers=bearer(token_northgrid_admin),
    )
    assert created.status_code == 201
    request_id = created.json()["id"]

    resp = client.post(
        f"{API}/jit/requests/{request_id}/approve",
        json={},
        headers=bearer(token_northgrid_viewer),
    )
    assert resp.status_code == 403


def test_engineer_cannot_approve_jit_request(client, token_northgrid_engineer, token_northgrid_admin):
    created = client.post(
        f"{API}/jit/requests",
        json={
            "tenant_id": 1,
            "asset_id": 1,
            "reason": "Field diagnostic access",
            "requested_permissions": "asset:jit_access",
            "requested_until": "2030-01-01T00:00:00Z",
        },
        headers=bearer(token_northgrid_admin),
    )
    assert created.status_code == 201
    request_id = created.json()["id"]

    resp = client.post(f"{API}/jit/requests/{request_id}/approve", json={}, headers=bearer(token_northgrid_engineer))
    assert resp.status_code == 403


def test_cross_tenant_query_forbidden_for_tenant_user(client, token_northgrid_engineer, tenant_ids):
    resp = client.get(f"{API}/assets", params={"tenant_id": tenant_ids["aquaflow"]}, headers=bearer(token_northgrid_engineer))
    assert resp.status_code == 403


def test_platform_admin_cross_tenant_read_allowed(client, token_platform, tenant_ids):
    resp = client.get(f"{API}/assets", params={"tenant_id": tenant_ids["aquaflow"]}, headers=bearer(token_platform))
    assert resp.status_code == 200
    assert len(resp.json()) == 3
