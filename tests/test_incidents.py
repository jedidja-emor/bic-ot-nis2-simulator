"""NIS2 Article 21/23 incident timer tests."""
from __future__ import annotations

from datetime import timedelta

from conftest import bearer
from app.timeutils import parse_iso

API = "/api/v1"


def _declare(client, token: str, tenant_id: int, title: str = "Coolant loss", severity: str = "high"):
    return client.post(
        f"{API}/incidents",
        json={
            "tenant_id": tenant_id,
            "title": title,
            "description": "Pump coolant leak detected; containment in progress.",
            "severity": severity,
            "article": "both",
        },
        headers=bearer(token),
    )


def _timers(client, token: str, tenant_id: int):
    return client.get(f"{API}/incidents/timers", params={"tenant_id": tenant_id}, headers=bearer(token))


def test_declare_computes_nis2_sla_timers(client, token_northgrid_admin, tenant_ids):
    resp = _declare(client, token_northgrid_admin, tenant_ids["northgrid"], title="Coolant loss")
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "open"
    assert body["severity"] == "high"
    assert body["article"] == "both"

    declared = parse_iso(body["declared_at"])
    early = parse_iso(body["early_warning_deadline"])
    notification = parse_iso(body["notification_deadline"])
    assert early - declared == timedelta(hours=24)
    assert notification - declared == timedelta(hours=72)


def test_early_warning_then_authority_notification_flow(client, token_northgrid_admin, tenant_ids):
    declared = _declare(client, token_northgrid_admin, tenant_ids["northgrid"], title="Coolant loss")
    assert declared.status_code == 201
    incident_id = declared.json()["id"]

    early = client.post(f"{API}/incidents/{incident_id}/early-warning", json={}, headers=bearer(token_northgrid_admin))
    assert early.status_code == 200
    assert early.json()["status"] == "early_warning_sent"
    assert early.json()["early_warning_sent_at"]
    assert early.json()["is_overdue"] is False

    notify = client.post(f"{API}/incidents/{incident_id}/notify", json={}, headers=bearer(token_northgrid_admin))
    assert notify.status_code == 200
    assert notify.json()["status"] == "notified_authority"
    assert notify.json()["notification_sent_at"]
    assert notify.json()["is_overdue"] is False

    timers = _timers(client, token_northgrid_admin, tenant_ids["northgrid"])
    assert timers.status_code == 200
    entry = next(t for t in timers.json() if t["id"] == incident_id)
    assert entry["timer_state"] == "notified"
    assert entry["is_overdue"] is False
    assert entry["time_remaining_seconds"] == 0


def test_notify_requires_early_warning_sent(client, token_northgrid_admin, tenant_ids):
    declared = _declare(client, token_northgrid_admin, tenant_ids["northgrid"], title="Coolant loss")
    incident_id = declared.json()["id"]

    notify = client.post(f"{API}/incidents/{incident_id}/notify", json={}, headers=bearer(token_northgrid_admin))
    assert notify.status_code == 409


def test_early_warning_requires_open_status(client, token_northgrid_admin, tenant_ids):
    declared = _declare(client, token_northgrid_admin, tenant_ids["northgrid"], title="Coolant loss")
    incident_id = declared.json()["id"]

    early = client.post(f"{API}/incidents/{incident_id}/early-warning", json={}, headers=bearer(token_northgrid_admin))
    assert early.status_code == 200

    again = client.post(f"{API}/incidents/{incident_id}/early-warning", json={}, headers=bearer(token_northgrid_admin))
    assert again.status_code == 409


def test_timers_early_warning_pending_then_overdue(client, token_northgrid_admin, tenant_ids, monkeypatch):
    declared = _declare(client, token_northgrid_admin, tenant_ids["northgrid"], title="Coolant loss")
    incident_id = declared.json()["id"]
    declared_at = declared.json()["declared_at"]

    timers = _timers(client, token_northgrid_admin, tenant_ids["northgrid"])
    assert timers.status_code == 200
    entry = next(t for t in timers.json() if t["id"] == incident_id)
    assert entry["status"] == "open"
    assert entry["timer_state"] == "early_warning_pending"
    assert 0 < entry["time_remaining_seconds"] <= 24 * 3600
    assert entry["is_overdue"] is False

    shifted = parse_iso(declared_at) + timedelta(hours=25)
    monkeypatch.setattr("app.nis2.utcnow", lambda: shifted)
    monkeypatch.setattr("app.routers.incidents.utcnow", lambda: shifted)

    timers = _timers(client, token_northgrid_admin, tenant_ids["northgrid"])
    entry = next(t for t in timers.json() if t["id"] == incident_id)
    assert entry["timer_state"] == "early_warning_overdue"
    assert entry["is_overdue"] is True
    assert entry["time_remaining_seconds"] == 0


def test_authority_notification_overdue_flag(client, token_northgrid_admin, tenant_ids, monkeypatch):
    declared = _declare(client, token_northgrid_admin, tenant_ids["northgrid"], title="Coolant loss")
    incident_id = declared.json()["id"]

    early = client.post(f"{API}/incidents/{incident_id}/early-warning", json={}, headers=bearer(token_northgrid_admin))
    assert early.status_code == 200
    declared_at = declared.json()["declared_at"]

    shifted = parse_iso(declared_at) + timedelta(hours=73)
    monkeypatch.setattr("app.nis2.utcnow", lambda: shifted)

    notify = client.post(f"{API}/incidents/{incident_id}/notify", json={}, headers=bearer(token_northgrid_admin))
    assert notify.status_code == 200
    assert notify.json()["status"] == "notified_authority"
    assert notify.json()["is_overdue"] is True


def test_resolve_and_close_incident(client, token_northgrid_admin, tenant_ids):
    declared = _declare(client, token_northgrid_admin, tenant_ids["northgrid"], title="Coolant loss")
    incident_id = declared.json()["id"]

    resolved = client.patch(f"{API}/incidents/{incident_id}", json={"status": "resolved"}, headers=bearer(token_northgrid_admin))
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"
    assert resolved.json()["resolved_at"]

    closed = client.patch(f"{API}/incidents/{incident_id}", json={"status": "closed"}, headers=bearer(token_northgrid_admin))
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"
    assert closed.json()["closed_at"]

    timers = _timers(client, token_northgrid_admin, tenant_ids["northgrid"])
    entry = next(t for t in timers.json() if t["id"] == incident_id)
    assert entry["timer_state"] == "complete"


def test_incident_cross_tenant_access_forbidden(client, token_northgrid_engineer, token_aquaflow_admin, tenant_ids):
    declared = _declare(client, token_aquaflow_admin, tenant_ids["aquaflow"], title="Water pressure drop")
    assert declared.status_code == 201
    incident_id = declared.json()["id"]

    got = client.get(f"{API}/incidents/{incident_id}", headers=bearer(token_northgrid_engineer))
    assert got.status_code == 403

    declared_cross = client.post(
        f"{API}/incidents",
        json={
            "tenant_id": tenant_ids["aquaflow"],
            "title": "Cross tenant probe",
            "description": "Engineer probing another tenant incident.",
            "severity": "low",
            "article": "21",
        },
        headers=bearer(token_northgrid_engineer),
    )
    assert declared_cross.status_code == 403
