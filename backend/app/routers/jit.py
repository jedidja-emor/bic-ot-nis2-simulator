"""Just-In-Time vendor access request / grant lifecycle."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..crud import (
    jit_grant_to_dict,
    jit_request_to_dict,
    join_permissions,
    split_permissions,
)
from ..database import get_db
from ..deps import (
    enforce_any_permission,
    enforce_permission,
    enforce_tenant_membership,
    get_current_user,
    get_user_tenant_ids,
    is_platform_admin,
)
from ..jit import expire_stale_grants, grant_is_current
from ..models import (
    Asset,
    JITAccessGrant,
    JITAccessRequest,
    JITStatus,
    Permission,
    Tenant,
    User,
)
from ..schemas import JITApprove, JITReject, JITRequestCreate, JITRevoke
from ..timeutils import now_iso, parse_iso, to_iso, utcnow

router = APIRouter(prefix="/jit", tags=["jit"])


def _get_request(db: Session, request_id: int) -> JITAccessRequest:
    row = db.get(JITAccessRequest, request_id)
    if row is None:
        raise HTTPException(status_code=404, detail="JIT request not found")
    return row


def _get_grant(db: Session, grant_id: int) -> JITAccessGrant:
    row = db.get(JITAccessGrant, grant_id)
    if row is None:
        raise HTTPException(status_code=404, detail="JIT grant not found")
    return row


def _known_permission_codes(db: Session) -> set[str]:
    return {row[0] for row in db.query(Permission.code).all()}


def _validate_permission_codes(db: Session, codes: list[str]) -> list[str]:
    known = _known_permission_codes(db)
    unknown = [code for code in codes if code not in known]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown permission codes: {', '.join(unknown)}")
    if not codes:
        raise HTTPException(status_code=400, detail="At least one permission code is required")
    return codes


def _authorize_tenant_read(db: Session, user: User, tenant_id: int) -> None:
    enforce_tenant_membership(db, user, tenant_id)
    enforce_permission(db, user, "jit:read", tenant_id)


@router.get("/requests")
def list_requests(
    tenant_id: int | None = Query(default=None),
    status: JITStatus | None = Query(default=None),
    asset_id: int | None = Query(default=None),
    mine: bool = Query(default=False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(JITAccessRequest)
    if is_platform_admin(db, current_user):
        enforce_permission(db, current_user, "jit:read", tenant_id)
        if tenant_id is not None:
            query = query.filter(JITAccessRequest.tenant_id == tenant_id)
    else:
        allowed = get_user_tenant_ids(db, current_user)
        if tenant_id is not None:
            _authorize_tenant_read(db, current_user, tenant_id)
            allowed = [tenant_id]
        else:
            enforce_any_permission(db, current_user, "jit:read")
        if not allowed:
            return []
        query = query.filter(JITAccessRequest.tenant_id.in_(allowed))

    if status is not None:
        query = query.filter(JITAccessRequest.status == status.value)
    if asset_id is not None:
        query = query.filter(JITAccessRequest.asset_id == asset_id)
    if mine:
        query = query.filter(JITAccessRequest.requesting_user_id == current_user.id)
    return [jit_request_to_dict(row) for row in query.order_by(JITAccessRequest.id.desc()).all()]


@router.post("/requests", status_code=201)
def create_request(
    payload: JITRequestCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if db.get(Tenant, payload.tenant_id) is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    enforce_tenant_membership(db, current_user, payload.tenant_id)
    enforce_permission(db, current_user, "jit:request", payload.tenant_id)

    if payload.asset_id is not None:
        asset = db.get(Asset, payload.asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        if asset.tenant_id != payload.tenant_id:
            raise HTTPException(status_code=400, detail="Asset does not belong to tenant")

    requested_until = parse_iso(payload.requested_until)
    if requested_until is None or requested_until <= utcnow():
        raise HTTPException(status_code=400, detail="requested_until must be in the future")

    codes = _validate_permission_codes(db, split_permissions(payload.requested_permissions))
    now = now_iso()
    request = JITAccessRequest(
        tenant_id=payload.tenant_id,
        requesting_user_id=current_user.id,
        asset_id=payload.asset_id,
        reason=payload.reason,
        requested_permissions=join_permissions(codes),
        requested_until=to_iso(requested_until),
        status=JITStatus.pending.value,
        created_at=now,
        updated_at=now,
    )
    db.add(request)
    db.flush()
    write_audit(
        db,
        tenant_id=request.tenant_id,
        actor_user_id=current_user.id,
        action="jit:request",
        target_type="jit_request",
        target_id=request.id,
        details={
            "asset_id": request.asset_id,
            "requested_permissions": codes,
            "requested_until": request.requested_until,
            "reason": request.reason,
        },
    )
    db.commit()
    return jit_request_to_dict(request)


@router.get("/requests/{request_id}")
def get_request(
    request_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    request = _get_request(db, request_id)
    _authorize_tenant_read(db, current_user, request.tenant_id)
    data = jit_request_to_dict(request)
    grants = (
        db.query(JITAccessGrant)
        .filter(JITAccessGrant.request_id == request.id)
        .order_by(JITAccessGrant.id.desc())
        .all()
    )
    data["grants"] = [jit_grant_to_dict(grant) for grant in grants]
    return data


@router.post("/requests/{request_id}/approve")
def approve_request(
    request_id: int,
    payload: JITApprove,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    request = _get_request(db, request_id)
    enforce_tenant_membership(db, current_user, request.tenant_id)
    enforce_permission(db, current_user, "jit:approve", request.tenant_id)

    if request.status != JITStatus.pending.value:
        raise HTTPException(status_code=409, detail=f"Request is not pending (status={request.status})")

    requested_codes = split_permissions(request.requested_permissions)
    if payload.granted_permissions is not None:
        granted_codes = split_permissions(payload.granted_permissions)
        granted_codes = [code for code in granted_codes if code in requested_codes]
    else:
        granted_codes = requested_codes
    granted_codes = _validate_permission_codes(db, granted_codes)

    requested_until = parse_iso(request.requested_until)
    assert requested_until is not None
    valid_until = parse_iso(payload.valid_until) if payload.valid_until is not None else requested_until
    if valid_until is None:
        valid_until = requested_until
    if valid_until > requested_until:
        valid_until = requested_until
    if valid_until <= utcnow():
        raise HTTPException(status_code=400, detail="valid_until must be in the future")

    if request.asset_id is not None:
        existing = (
            db.query(JITAccessGrant)
            .join(JITAccessRequest, JITAccessRequest.id == JITAccessGrant.request_id)
            .filter(
                JITAccessGrant.grantee_user_id == request.requesting_user_id,
                JITAccessGrant.asset_id == request.asset_id,
                JITAccessGrant.is_active.is_(True),
                JITAccessGrant.valid_until > now_iso(),
                JITAccessRequest.tenant_id == request.tenant_id,
            )
            .first()
        )
        if existing is not None:
            raise HTTPException(
                status_code=409,
                detail="Grantee already has an active JIT grant for this asset",
            )

    now = now_iso()
    request.status = JITStatus.approved.value
    request.approved_by = current_user.id
    request.approved_at = now
    request.updated_at = now

    grant = JITAccessGrant(
        request_id=request.id,
        grantee_user_id=request.requesting_user_id,
        asset_id=request.asset_id,
        granted_permissions=join_permissions(granted_codes),
        valid_from=now,
        valid_until=to_iso(valid_until),
        is_active=True,
        created_at=now,
    )
    db.add(grant)
    db.flush()
    write_audit(
        db,
        tenant_id=request.tenant_id,
        actor_user_id=current_user.id,
        action="jit:grant",
        target_type="jit_grant",
        target_id=grant.id,
        details={
            "request_id": request.id,
            "grantee_user_id": grant.grantee_user_id,
            "asset_id": grant.asset_id,
            "granted_permissions": granted_codes,
            "valid_until": grant.valid_until,
        },
    )
    db.commit()
    return {"request": jit_request_to_dict(request), "grant": jit_grant_to_dict(grant)}


@router.post("/requests/{request_id}/reject")
def reject_request(
    request_id: int,
    payload: JITReject,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    request = _get_request(db, request_id)
    enforce_tenant_membership(db, current_user, request.tenant_id)
    enforce_permission(db, current_user, "jit:approve", request.tenant_id)

    if request.status != JITStatus.pending.value:
        raise HTTPException(status_code=409, detail=f"Request is not pending (status={request.status})")

    now = now_iso()
    request.status = JITStatus.rejected.value
    request.approved_by = current_user.id
    request.approved_at = now
    request.updated_at = now
    write_audit(
        db,
        tenant_id=request.tenant_id,
        actor_user_id=current_user.id,
        action="jit:reject",
        target_type="jit_request",
        target_id=request.id,
        details={"reason": payload.reason},
    )
    db.commit()
    return jit_request_to_dict(request)


@router.get("/grants")
def list_grants(
    tenant_id: int | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    asset_id: int | None = Query(default=None),
    grantee_user_id: int | None = Query(default=None),
    mine: bool = Query(default=False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    platform = is_platform_admin(db, current_user)
    allowed: list[int] = []
    if platform:
        enforce_permission(db, current_user, "jit:read", tenant_id)
    else:
        allowed = get_user_tenant_ids(db, current_user)
        if tenant_id is not None:
            _authorize_tenant_read(db, current_user, tenant_id)
            allowed = [tenant_id]
        else:
            enforce_any_permission(db, current_user, "jit:read")
        if not allowed:
            return []

    if platform:
        expire_stale_grants(db, tenant_id=tenant_id)
    else:
        for allowed_tenant in allowed:
            expire_stale_grants(db, tenant_id=allowed_tenant)
    db.commit()

    query = db.query(JITAccessGrant).join(
        JITAccessRequest, JITAccessRequest.id == JITAccessGrant.request_id
    )
    if platform:
        if tenant_id is not None:
            query = query.filter(JITAccessRequest.tenant_id == tenant_id)
    else:
        query = query.filter(JITAccessRequest.tenant_id.in_(allowed))

    if is_active is not None:
        query = query.filter(JITAccessGrant.is_active.is_(is_active))
    if asset_id is not None:
        query = query.filter(JITAccessGrant.asset_id == asset_id)
    if grantee_user_id is not None:
        query = query.filter(JITAccessGrant.grantee_user_id == grantee_user_id)
    if mine:
        query = query.filter(JITAccessGrant.grantee_user_id == current_user.id)
    return [jit_grant_to_dict(row) for row in query.order_by(JITAccessGrant.id.desc()).all()]


@router.get("/my-grants")
def my_grants(
    include_inactive: bool = Query(default=False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce_any_permission(db, current_user, "jit:read")
    if is_platform_admin(db, current_user):
        expire_stale_grants(db)
    else:
        for allowed_tenant in get_user_tenant_ids(db, current_user):
            expire_stale_grants(db, tenant_id=allowed_tenant)
    db.commit()
    query = db.query(JITAccessGrant).filter(JITAccessGrant.grantee_user_id == current_user.id)
    if not include_inactive:
        query = query.filter(
            JITAccessGrant.is_active.is_(True),
            JITAccessGrant.valid_until > now_iso(),
        )
    return [jit_grant_to_dict(row) for row in query.order_by(JITAccessGrant.id.desc()).all()]


@router.get("/grants/{grant_id}")
def get_grant(
    grant_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    grant = _get_grant(db, grant_id)
    request = db.get(JITAccessRequest, grant.request_id)
    if request is None:
        raise HTTPException(status_code=404, detail="JIT request not found")
    _authorize_tenant_read(db, current_user, request.tenant_id)
    expire_stale_grants(db, tenant_id=request.tenant_id)
    db.commit()
    db.refresh(grant)
    data = jit_grant_to_dict(grant)
    data["is_current"] = grant_is_current(grant)
    return data


@router.post("/grants/{grant_id}/revoke")
def revoke_grant(
    grant_id: int,
    payload: JITRevoke,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    grant = _get_grant(db, grant_id)
    request = db.get(JITAccessRequest, grant.request_id)
    if request is None:
        raise HTTPException(status_code=404, detail="JIT request not found")
    enforce_tenant_membership(db, current_user, request.tenant_id)
    enforce_permission(db, current_user, "jit:approve", request.tenant_id)

    if not grant.is_active:
        raise HTTPException(status_code=409, detail="Grant is not active")

    now = now_iso()
    grant.is_active = False
    grant.revoked_at = now
    grant.revoked_by = current_user.id
    if request.status == JITStatus.approved.value:
        request.status = JITStatus.revoked.value
        request.updated_at = now

    write_audit(
        db,
        tenant_id=request.tenant_id,
        actor_user_id=current_user.id,
        action="jit:revoke",
        target_type="jit_grant",
        target_id=grant.id,
        details={"request_id": request.id, "reason": payload.reason},
    )
    db.commit()
    return jit_grant_to_dict(grant)
