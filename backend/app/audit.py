"""Append-only, hash-chained audit ledger."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import AuditLog
from .timeutils import now_iso

GENESIS_HASH = "0" * 64


def canonical_details(details: Any) -> str:
    """Deterministic JSON representation used in the hash payload."""
    if details is None:
        return "{}"
    if isinstance(details, str):
        try:
            parsed = json.loads(details)
        except (TypeError, ValueError):
            parsed = details
        return json.dumps(parsed, sort_keys=True, separators=(",", ":"), default=str)
    return json.dumps(details, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(
    sequence_no: int,
    previous_hash: str,
    event_time: str,
    actor_user_id: int | None,
    action: str,
    target_type: str,
    target_id: str,
    details: str,
) -> str:
    payload = (
        f"{sequence_no}|{previous_hash}|{event_time}|{actor_user_id or ''}|"
        f"{action}|{target_type}|{target_id}|{details}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_audit(
    db: Session,
    *,
    action: str,
    target_type: str,
    target_id: Any,
    tenant_id: int | None = None,
    actor_user_id: int | None = None,
    details: Any = None,
    event_time: str | None = None,
) -> AuditLog:
    """Append one row to the audit chain.

    The caller controls the surrounding transaction.  The row is flushed so a
    subsequent audit write in the same transaction sees the new sequence/hash.
    """
    max_seq = db.query(func.max(AuditLog.sequence_no)).scalar()
    sequence_no = int(max_seq or 0) + 1

    if sequence_no == 1:
        previous_hash = GENESIS_HASH
    else:
        previous = (
            db.query(AuditLog)
            .filter(AuditLog.sequence_no == sequence_no - 1)
            .first()
        )
        previous_hash = previous.hash if previous else GENESIS_HASH

    ts = event_time or now_iso()
    details_text = canonical_details(details)
    row = AuditLog(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        details=details_text,
        event_time=ts,
        sequence_no=sequence_no,
        previous_hash=previous_hash,
        hash=compute_hash(
            sequence_no,
            previous_hash,
            ts,
            actor_user_id,
            action,
            target_type,
            str(target_id),
            details_text,
        ),
        created_at=now_iso(),
    )
    db.add(row)
    db.flush()
    return row


def verify_chain(db: Session, up_to_sequence: int | None = None) -> dict[str, Any]:
    """Recompute the chain and return a verification report."""
    query = db.query(AuditLog).order_by(AuditLog.sequence_no.asc())
    if up_to_sequence is not None:
        query = query.filter(AuditLog.sequence_no <= up_to_sequence)

    expected_sequence = 1
    expected_previous = GENESIS_HASH
    checked = 0

    for row in query.all():
        checked += 1
        if row.sequence_no != expected_sequence:
            return {
                "valid": False,
                "checked_count": checked,
                "first_mismatch": {
                    "entry_id": row.id,
                    "sequence_no": row.sequence_no,
                    "reason": "sequence_gap",
                    "expected_sequence": expected_sequence,
                    "actual_sequence": row.sequence_no,
                },
            }
        if row.previous_hash != expected_previous:
            return {
                "valid": False,
                "checked_count": checked,
                "first_mismatch": {
                    "entry_id": row.id,
                    "sequence_no": row.sequence_no,
                    "reason": "previous_hash_mismatch",
                    "expected": expected_previous,
                    "actual": row.previous_hash,
                },
            }
        recomputed = compute_hash(
            row.sequence_no,
            row.previous_hash,
            row.event_time,
            row.actor_user_id,
            row.action,
            row.target_type,
            row.target_id,
            row.details,
        )
        if recomputed != row.hash:
            return {
                "valid": False,
                "checked_count": checked,
                "first_mismatch": {
                    "entry_id": row.id,
                    "sequence_no": row.sequence_no,
                    "reason": "hash_mismatch",
                    "expected": recomputed,
                    "actual": row.hash,
                },
            }
        expected_previous = row.hash
        expected_sequence += 1

    return {"valid": True, "checked_count": checked, "first_mismatch": None}


def audit_to_dict(row: AuditLog) -> dict[str, Any]:
    try:
        details: Any = json.loads(row.details)
    except (TypeError, ValueError):
        details = row.details
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "actor_user_id": row.actor_user_id,
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "details": details,
        "event_time": row.event_time,
        "sequence_no": row.sequence_no,
        "previous_hash": row.previous_hash,
        "hash": row.hash,
        "created_at": row.created_at,
    }
