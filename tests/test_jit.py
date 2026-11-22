"""Just-In-Time vendor access lifecycle tests."""
from __future__ import annotations

from conftest import bearer

from app.models import JITAccessGrant

API = "/api/v1"

FUTURE = "2030-01-01T00:00:00Z"


def _create_request(client, token, tenant_id: int, asset_id: int, permissions: str = "asset:jit_access"):
    return client.post(
        f"{API}/jit/requests",
        json={
            "tenant_id": tenant_id,
            "asset_id": asset_id,
            "reason": "Field diagnostic access",
            "requested_permissions": permissions,
            "requested_until": FUTURE,
        },
        headers=bearer(token),
    )


def test_jit_full_lifecycle_vendor_request_approve_grant_action_revoke(client, token_northgrid_vendor, token_northgrid_admin, db_session):
    from app.models import Asset

    plc = db_session.query(Asset).filter(Asset.tenant_id == 1, Asset.asset_tag == "PLC-001").one()
    req = _create_request(client, token_northgrid_vendor, 1, plc.id)
    assert req.status_code == 201
    assert req.json()["status"] == "pending"

    appr = client.post(
        f"{API}/jit/requests/{req.json()['id']}/approve",
        json={"granted_permissions": "asset:jit_access", "valid_until": FUTURE},
        headers=bearer(token_northgrid_admin),
    )
    assert appr.status_code == 200
    assert appr.json()["request"]["status"] == "approved"
    grant = appr.json()["grant"]
    assert grant["is_active"] is True
    assert grant["grantee_user_id"] is not None

    action = client.post(
        f"{API}/assets/{plc.id}/jit-action",
        json={"action": "read"},
        headers=bearer(token_northgrid_vendor),
    )
    assert action.status_code == 200
    assert action.json()["detail"].startswith("Simulated OT action")

    revoked = client.post(
        f"{API}/jit/grants/{grant['id']}/revoke",
        json={"reason": "Diagnostic completed"},
        headers=bearer(token_northgrid_admin),
    )
    assert revoked.status_code == 200
    assert revoked.json()["is_active"] is False

    action_after_revoke = client.post(
        f"{API}/assets/{plc.id}/jit-action",
        json={"action": "read"},
        headers=bearer(token_northgrid_vendor),
    )
    assert action_after_revoke.status_code == 403


def test_jit_cannot_approve_twice(client, token_northgrid_admin, token_northgrid_vendor, db_session):
    from app.models import Asset

    plc = db_session.query(Asset).filter(Asset.tenant_id == 1, Asset.asset_tag == "PLC-001").one()
    req = _create_request(client, token_northgrid_vendor, 1, plc.id)
    assert req.status_code == 201
    assert client.post(
        f"{API}/jit/requests/{req.json()['id']}/approve",
        json={"granted_permissions": "asset:jit_access", "valid_until": FUTURE},
        headers=bearer(token_northgrid_admin),
    ).status_code == 200

    second = client.post(
        f"{API}/jit/requests/{req.json()['id']}/approve",
        json={"granted_permissions": "asset:jit_access", "valid_until": FUTURE},
        headers=bearer(token_northgrid_admin),
    )
    assert second.status_code == 409


def test_jit_grant_expires_after_valid_until(client, token_northgrid_admin, token_northgrid_vendor, db_session):
    from app.models import Asset

    plc = db_session.query(Asset).filter(Asset.tenant_id == 1, Asset.asset_tag == "PLC-001").one()
    req = _create_request(client, token_northgrid_vendor, 1, plc.id)
    assert req.status_code == 201
    appr = client.post(
        f"{API}/jit/requests/{req.json()['id']}/approve",
        json={"granted_permissions": "asset:jit_access", "valid_until": FUTURE},
        headers=bearer(token_northgrid_admin),
    )
    assert appr.status_code == 200
    grant_id = appr.json()["grant"]["id"]

    ok = client.post(
        f"{API}/assets/{plc.id}/jit-action",
        json={"action": "read"},
        headers=bearer(token_northgrid_vendor),
    )
    assert ok.status_code == 200

    grant = db_session.get(JITAccessGrant, grant_id)
    assert grant is not None
    grant.valid_until = "2020-01-01T00:00:00Z"
    db_session.commit()

    expired = client.post(
        f"{API}/assets/{plc.id}/jit-action",
        json={"action": "read"},
        headers=bearer(token_northgrid_vendor),
    )
    assert expired.status_code == 403


def test_jit_double_active_grant_conflict(client, token_northgrid_admin, token_northgrid_vendor, db_session):
    from app.models import Asset

    plc = db_session.query(Asset).filter(Asset.tenant_id == 1, Asset.asset_tag == "PLC-001").one()
    first = _create_request(client, token_northgrid_vendor, 1, plc.id)
    assert first.status_code == 201
    assert client.post(
        f"{API}/jit/requests/{first.json()['id']}/approve",
        json={"granted_permissions": "asset:jit_access", "valid_until": FUTURE},
        headers=bearer(token_northgrid_admin),
    ).status_code == 200

    second = _create_request(client, token_northgrid_vendor, 1, plc.id)
    assert second.status_code == 201
    dup = client.post(
        f"{API}/jit/requests/{second.json()['id']}/approve",
        json={"granted_permissions": "asset:jit_access", "valid_until": FUTURE},
        headers=bearer(token_northgrid_admin),
    )
    assert dup.status_code == 409


def test_jit_request_validation_errors(client, token_northgrid_vendor, tenant_ids, db_session):
    from app.models import Asset

    plc_aqua = db_session.query(Asset).filter(Asset.tenant_id == tenant_ids["aquaflow"], Asset.asset_tag == "PLC-101").one()

    # requested_until in the past -> rejected.
    past = client.post(
        f"{API}/jit/requests",
        json={
            "tenant_id": tenant_ids["northgrid"],
            "asset_id": 1,
            "reason": "Field diagnostic access",
            "requested_permissions": "asset:jit_access",
            "requested_until": "2020-01-01T00:00:00Z",
        },
        headers=bearer(token_northgrid_vendor),
    )
    assert past.status_code == 400

    # unknown permission code -> rejected.
    bad_perm = client.post(
        f"{API}/jit/requests",
        json={
            "tenant_id": tenant_ids["northgrid"],
            "asset_id": 1,
            "reason": "Field diagnostic access",
            "requested_permissions": "asset:bogus:perm",
            "requested_until": FUTURE,
        },
        headers=bearer(token_northgrid_vendor),
    )
    assert bad_perm.status_code == 400

    # cross-tenant asset reference -> rejected.
    cross = client.post(
        f"{API}/jit/requests",
        json={
            "tenant_id": tenant_ids["northgrid"],
            "asset_id": plc_aqua.id,
            "reason": "Field diagnostic access",
            "requested_permissions": "asset:jit_access",
            "requested_until": FUTURE,
        },
        headers=bearer(token_northgrid_vendor),
    )
    assert cross.status_code == 400


def test_jit_cross_tenant_access_forbidden(client, token_northgrid_engineer, tenant_ids):
    resp = client.get(f"{API}/jit/requests", params={"tenant_id": tenant_ids["aquaflow"]}, headers=bearer(token_northgrid_engineer))
    assert resp.status_code == 403
