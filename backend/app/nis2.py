"""NIS2 Article 21 (24h early warning) / Article 23 (72h notification) timers."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from .models import Incident, IncidentStatus
from .timeutils import parse_iso, to_iso, utcnow

EARLY_WARNING_HOURS = 24
NOTIFICATION_HOURS = 72


def deadlines_for(declared_at: datetime) -> tuple[str, str]:
    """Return ``(early_warning_deadline, notification_deadline)`` ISO strings."""
    early = to_iso(declared_at + timedelta(hours=EARLY_WARNING_HOURS))
    notification = to_iso(declared_at + timedelta(hours=NOTIFICATION_HOURS))
    assert early is not None and notification is not None
    return early, notification


def compute_timer(incident: Incident, now: datetime | None = None) -> dict[str, Any]:
    """Derive the read-only NIS2 timer state for an incident."""
    current = now or utcnow()
    early_deadline = parse_iso(incident.early_warning_deadline)
    notification_deadline = parse_iso(incident.notification_deadline)
    assert early_deadline is not None and notification_deadline is not None

    status = incident.status
    timer_state = "unknown"
    deadline: datetime | None = None
    remaining = 0
    is_overdue = False

    if status == IncidentStatus.open.value:
        deadline = early_deadline
        if current < early_deadline:
            timer_state = "early_warning_pending"
            remaining = int((early_deadline - current).total_seconds())
        else:
            timer_state = "early_warning_overdue"
            remaining = 0
            is_overdue = True
    elif status == IncidentStatus.early_warning_sent.value:
        deadline = notification_deadline
        if current < notification_deadline:
            timer_state = "notification_pending"
            remaining = int((notification_deadline - current).total_seconds())
        else:
            timer_state = "notification_overdue"
            remaining = 0
            is_overdue = True
    elif status == IncidentStatus.notified_authority.value:
        timer_state = "notified"
        deadline = notification_deadline
        remaining = 0
    elif status in (IncidentStatus.resolved.value, IncidentStatus.closed.value):
        timer_state = "complete"
        deadline = notification_deadline
        remaining = 0

    early_sent = parse_iso(incident.early_warning_sent_at)
    notification_sent = parse_iso(incident.notification_sent_at)
    return {
        "timer_state": timer_state,
        "time_remaining_seconds": max(0, remaining),
        "is_overdue": is_overdue,
        "deadline": to_iso(deadline),
        "early_warning_deadline": incident.early_warning_deadline,
        "notification_deadline": incident.notification_deadline,
        "early_warning_overdue": bool(early_sent and early_sent > early_deadline),
        "notification_overdue": bool(
            notification_sent and notification_sent > notification_deadline
        ),
    }


def is_early_warning_late(incident: Incident, at: datetime | None = None) -> bool:
    deadline = parse_iso(incident.early_warning_deadline)
    current = at or utcnow()
    return bool(deadline and current > deadline)


def is_notification_late(incident: Incident, at: datetime | None = None) -> bool:
    deadline = parse_iso(incident.notification_deadline)
    current = at or utcnow()
    return bool(deadline and current > deadline)
