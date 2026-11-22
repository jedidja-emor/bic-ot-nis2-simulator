"""Hash-chained audit log tests."""
from __future__ import annotations

from conftest import bearer

from app.models import AuditLog

API = "/api/v1"


def test_audit_chain_verifies_valid_after_activity(client, token_platform):
    # Login + (seed writes a system entry) -> chain should verify cleanly.
    login = client.post(
        f"{API}/auth/login",
        json={"email": "admin@northgrid.io", "password": "NorthGrid123!"},
    )
    assert login.status_code == 200

    resp = client.get(f"{API}/audit/verify", headers=bearer(token_platform))
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True
    assert body["checked_count"] >= 1
    assert body["first_mismatch"] is None


def test_audit_logs_filter_by_action(client, token_platform):
    client.post(
        f"{API}/auth/login",
        json={"email": "admin@northgrid.io", "password": "NorthGrid123!"},
    )
    resp = client.get(f"{API}/audit/logs", params={"action": "auth:login", "limit": 50}, headers=bearer(token_platform))
    assert resp.status_code == 200
    entries = resp.json()
    assert len(entries) >= 1
    for entry in entries:
        assert entry["action"] == "auth:login"


def test_audit_tamper_detection(client, token_platform, db_session):
    resp = client.get(f"{API}/audit/verify", headers=bearer(token_platform))
    assert resp.json()["valid"] is True

    entries = (
        db_session.query(AuditLog)
        .order_by(AuditLog.sequence_no.asc())
        .all()
    )
    victim = entries[-1]
    original_hash = victim.hash
    victim.hash = "f" * 64
    db_session.commit()

    resp = client.get(f"{API}/audit/verify", headers=bearer(token_platform))
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is False
    assert body["first_mismatch"] is not None
    assert body["first_mismatch"]["reason"] == "hash_mismatch"
    assert body["first_mismatch"]["sequence_no"] == victim.sequence_no
    assert body["first_mismatch"]["actual"] == "f" * 64
    assert body["first_mismatch"]["expected"] != "f" * 64


def test_audit_genesis_previous_hash_is_zero(client, token_platform, db_session):
    entries = (
        db_session.query(AuditLog)
        .order_by(AuditLog.sequence_no.asc())
        .all()
    )
    first = entries[0]
    assert first.sequence_no == 1
    assert first.previous_hash == "0" * 64


def test_audit_cross_tenant_logs_forbidden(client, token_northgrid_viewer, tenant_ids):
    resp = client.get(
        f"{API}/audit/logs",
        params={"tenant_id": tenant_ids["aquaflow"]},
        headers=bearer(token_northgrid_viewer),
    )
    assert resp.status_code == 403
