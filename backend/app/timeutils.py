"""UTC / ISO-8601 helpers shared by the backend."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utcnow() -> datetime:
    """Timezone-aware UTC now, truncated to whole seconds."""
    return datetime.now(timezone.utc).replace(microsecond=0)


def to_iso(value: datetime | None) -> str | None:
    """Serialize a datetime to the canonical ``YYYY-MM-DDTHH:MM:SSZ`` form."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime(ISO_FORMAT)


def now_iso() -> str:
    return to_iso(utcnow())


def parse_iso(value: str | datetime | None) -> datetime | None:
    """Parse an ISO-8601 timestamp into an aware UTC datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            # Last-resort support for legacy "YYYY-MM-DD HH:MM:SS" values.
            dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def add_hours(value: datetime | str, hours: int) -> str:
    base = parse_iso(value)
    assert base is not None
    return to_iso(base + timedelta(hours=hours))  # type: ignore[return-value]
