"""Static frontend/API contract smoke tests."""
from __future__ import annotations

from pathlib import Path

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"


def _read(relpath: str) -> str:
    return (FRONTEND_DIR / relpath).read_text(encoding="utf-8")


def test_frontend_incidents_module_calls_timers_endpoint():
    js = _read("static/js/incidents.js")
    assert "/incidents/timers" in js
    for field in [
        "early_warning_deadline",
        "notification_deadline",
        "timer_state",
        "is_overdue",
        "early_warning_sent_at",
        "notification_sent_at",
    ]:
        assert field in js, f"incidents.js missing timer field {field}"


def test_frontend_dashboard_uses_overdue_flag_and_timer_state():
    js = _read("static/js/dashboard.js")
    assert "is_overdue" in js
    assert "timer_state" in js


def test_frontend_audit_module_calls_verify_endpoint():
    js = _read("static/js/audit.js")
    assert "/audit/verify" in js
    assert "/audit/logs" in js


def test_frontend_jit_module_calls_grant_action_endpoints():
    js = _read("static/js/jit.js")
    assert "/jit/requests" in js
    assert "/jit/my-grants" in js
    assert "/jit/grants" in js
    assert "/jit-action" in js
