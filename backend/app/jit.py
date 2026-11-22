"""Just-In-Time access lifecycle helpers and time-bound grant enforcement."""
from __future__ import annotations

from sqlalchemy.orm import Session

from .audit import write_audit
from .crud import split_permissions
from .models import JITAccessGrant, JITAccessRequest, JITStatus
from .timeutils import now_iso


def grant_is_current(grant: JITAccessGrant, now: str | None = None) -> bool:
    """A grant is usable only while active and inside its validity window."""
    if not grant.is_active:
        return False
    current = now or now_iso()
    return grant.valid_from <= current < grant.valid_until


def active_grants_query(db: Session, tenant_id: int | None = None):
    query = db.query(JITAccessGrant).join(
        JITAccessRequest, JITAccessRequest.id == JITAccessGrant.request_id
    ).filter(
        JITAccessGrant.is_active.is_(True),
        JITAccessGrant.valid_from <= now_iso(),
        JITAccessGrant.valid_until > now_iso(),
        JITAccessRequest.status == JITStatus.approved.value,
    )
    if tenant_id is not None:
        query = query.filter(JITAccessRequest.tenant_id == tenant_id)
    return query


def has_active_grant(
    db: Session,
    *,
    user_id: int,
    tenant_id: int,
    asset_id: int | None = None,
    permission_code: str | None = None,
) -> bool:
    query = (
        db.query(JITAccessGrant)
        .join(JITAccessRequest, JITAccessRequest.id == JITAccessGrant.request_id)
        .filter(
            JITAccessGrant.grantee_user_id == user_id,
            JITAccessGrant.is_active.is_(True),
            JITAccessGrant.valid_from <= now_iso(),
            JITAccessGrant.valid_until > now_iso(),
            JITAccessRequest.tenant_id == tenant_id,
            JITAccessRequest.status == JITStatus.approved.value,
        )
    )
    if asset_id is not None:
        query = query.filter(JITAccessGrant.asset_id == asset_id)
    grants = query.all()
    if permission_code is None:
        return bool(grants)
    return any(permission_code in split_permissions(grant.granted_permissions) for grant in grants)


def expire_stale_grants(db: Session, tenant_id: int | None = None) -> int:
    """Mark elapsed grants/requests expired. Returns number of grants expired.

    Called on reads of grants/assets so the simulator behaves correctly even
    without a background scheduler.
    """
    current = now_iso()
    query = (
        db.query(JITAccessGrant)
        .join(JITAccessRequest, JITAccessRequest.id == JITAccessGrant.request_id)
        .filter(JITAccessGrant.is_active.is_(True), JITAccessGrant.valid_until <= current)
    )
    if tenant_id is not None:
        query = query.filter(JITAccessRequest.tenant_id == tenant_id)

    count = 0
    for grant in query.all():
        request = db.get(JITAccessRequest, grant.request_id)
        grant.is_active = False
        if request is not None:
            request.status = JITStatus.expired.value
            request.updated_at = current
        count += 1
        write_audit(
            db,
            tenant_id=request.tenant_id if request else None,
            actor_user_id=None,
            action="jit:expire",
            target_type="jit_grant",
            target_id=grant.id,
            details={
                "grant_id": grant.id,
                "request_id": grant.request_id,
                "valid_until": grant.valid_until,
                "reason": "validity_window_elapsed",
            },
        )
    if count:
        db.flush()
    return count


def grant_usable_by(grant: JITAccessGrant, user_id: int, permission_code: str) -> bool:
    return (
        grant.grantee_user_id == user_id
        and grant_is_current(grant)
        and permission_code in split_permissions(grant.granted_permissions)
    )


def active_grant_for_user_asset(
    db: Session,
    *,
    user_id: int,
    tenant_id: int,
    asset_id: int,
    permission_code: str,
) -> JITAccessGrant | None:
    expire_stale_grants(db, tenant_id=tenant_id)
    current = now_iso()
    grants = (
        db.query(JITAccessGrant)
        .join(JITAccessRequest, JITAccessRequest.id == JITAccessGrant.request_id)
        .filter(
            JITAccessGrant.grantee_user_id == user_id,
            JITAccessGrant.asset_id == asset_id,
            JITAccessGrant.is_active.is_(True),
            JITAccessGrant.valid_from <= current,
            JITAccessGrant.valid_until > current,
            JITAccessRequest.tenant_id == tenant_id,
            JITAccessRequest.status == JITStatus.approved.value,
        )
        .all()
    )
    for grant in grants:
        if permission_code in split_permissions(grant.granted_permissions):
            return grant
    return None
