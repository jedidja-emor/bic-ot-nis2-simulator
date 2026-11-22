"""Audit log browsing and hash-chain verification."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from ..audit import audit_to_dict, verify_chain
from ..database import get_db
from ..deps import (
    enforce_any_permission,
    enforce_permission,
    enforce_tenant_membership,
    get_current_user,
    get_user_tenant_ids,
    is_platform_admin,
)
from ..models import AuditLog, User
from ..timeutils import parse_iso, to_iso

router = APIRouter(prefix="/audit", tags=["audit"])


def _time_bound(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    parsed = parse_iso(value)
    if parsed is None:
        raise HTTPException(status_code=400, detail=f"Invalid {field} timestamp")
    return to_iso(parsed)


@router.get("/logs")
def list_logs(
    response: Response,
    tenant_id: int | None = Query(default=None),
    action: str | None = Query(default=None),
    actor_user_id: int | None = Query(default=None),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(AuditLog)

    if is_platform_admin(db, current_user):
        enforce_permission(db, current_user, "audit:read", None)
        if tenant_id is not None:
            query = query.filter(AuditLog.tenant_id == tenant_id)
    else:
        allowed = get_user_tenant_ids(db, current_user)
        if tenant_id is not None:
            enforce_tenant_membership(db, current_user, tenant_id)
            enforce_permission(db, current_user, "audit:read", tenant_id)
            allowed = [tenant_id]
        else:
            enforce_any_permission(db, current_user, "audit:read")
        if not allowed:
            response.headers["X-Total-Count"] = "0"
            return []
        query = query.filter(AuditLog.tenant_id.in_(allowed))

    if action:
        query = query.filter(AuditLog.action == action)
    if actor_user_id is not None:
        query = query.filter(AuditLog.actor_user_id == actor_user_id)
    since_iso = _time_bound(since, "since")
    until_iso = _time_bound(until, "until")
    if since_iso:
        query = query.filter(AuditLog.event_time >= since_iso)
    if until_iso:
        query = query.filter(AuditLog.event_time <= until_iso)

    total = query.count()
    rows = (
        query.order_by(AuditLog.sequence_no.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    response.headers["X-Total-Count"] = str(total)
    return [audit_to_dict(row) for row in rows]


@router.get("/verify")
def verify_full_chain(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce_any_permission(db, current_user, "audit:read")
    return verify_chain(db)


@router.get("/verify/{entry_id}")
def verify_prefix(
    entry_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce_any_permission(db, current_user, "audit:read")
    entry = db.get(AuditLog, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Audit entry not found")

    if not is_platform_admin(db, current_user):
        allowed = set(get_user_tenant_ids(db, current_user))
        if entry.tenant_id not in allowed:
            raise HTTPException(status_code=403, detail="Cross-tenant audit access denied")

    result = verify_chain(db, up_to_sequence=entry.sequence_no)
    result["entry_id"] = entry.id
    result["sequence_no"] = entry.sequence_no
    return result
