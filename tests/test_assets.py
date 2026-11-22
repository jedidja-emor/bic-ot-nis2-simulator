"""OT fleet asset CRUD, tenant scoping and JIT-linked behaviour tests."""
from __future__ import annotations

from conftest import bearer

from app.models import Asset

API = "/api/v1"


def _auth_headers(token: str) -> dict:
    return bearer(token)


def _create_asset(client, token: str, tenant_id: int, asset_tag: str, status: str = "online"):
    return client.post(
        f"{API}/assets",
        json={
            "tenant_id": tenant_id,
            "asset_tag": asset_tag,
            "name": f"QA Asset {asset_tag}",
            "type": "PLC",
            "site": "QA Site",
            "status": status,
        },
        headers=_auth_headers(token),
    )


def test_tenant_assets_are_isolated_per_tenant(client, token_northgrid_admin, tenant_ids):
    resp = client.get(f"{API}/assets", params={"tenant_id": tenant_ids["northgrid"]}, headers=_auth_headers(token_northgrid_admin))
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 4
    assert {a["asset_tag"] for a in body} == {"PLC-001", "RTU-001", "HMI-001", "SENSOR-001"}
    assert all(a["tenant_id"] == tenant_ids["northgrid"] for a in body)


def test_asset_crud_lifecycle(client, token_northgrid_admin, tenant_ids):
    created = _create_asset(client, token_northgrid_admin, tenant_ids["northgrid"], "PLC-QA-1")
    assert created.status_code == 201
    asset = created.json()
    asset_id = asset["id"]

    patched = client.patch(f"{API}/assets/{asset_id}", json={"status": "maintenance"}, headers=_auth_headers(token_northgrid_admin))
    assert patched.status_code == 200
    assert patched.json()["status"] == "maintenance"

    deleted = client.delete(f"{API}/assets/{asset_id}", headers=_auth_headers(token_northgrid_admin))
    assert deleted.status_code == 200

    got = client.get(f"{API}/assets/{asset_id}", headers=_auth_headers(token_northgrid_admin))
    assert got.status_code == 404


def test_duplicate_asset_tag_rejected(client, token_northgrid_admin, tenant_ids):
    resp = _create_asset(client, token_northgrid_admin, tenant_ids["northgrid"], "PLC-001")
    assert resp.status_code == 409


def test_cross_tenant_asset_access_forbidden(client, token_northgrid_engineer, tenant_ids, db_session):
    asset = db_session.query(Asset).filter(
        Asset.tenant_id == tenant_ids["aquaflow"],
        Asset.asset_tag == "PLC-101",
    ).one()
    resp = client.get(f"{API}/assets/{asset.id}", headers=_auth_headers(token_northgrid_engineer))
    assert resp.status_code == 403


def test_cross_tenant_asset_create_forbidden(client, token_northgrid_admin, tenant_ids, db_session):
    # northgrid admin may not create assets in another tenant.
    resp = _create_asset(client, token_northgrid_admin, tenant_ids["aquaflow"], "PLC-999")
    assert resp.status_code == 403
