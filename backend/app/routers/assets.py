"""OT fleet asset endpoints with tenant row-level isolation."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..crud import asset_to_dict, jit_grant_to_dict
from ..database import get_db
from ..deps import (
    enforce_any_permission,
    enforce_permission,
    enforce_tenant_membership,
    get_current_user,
    get_user_tenant_ids,
    is_platform_admin,
)
from ..jit import active_grant_for_user_asset, active_grants_query, expire_stale_grants
from ..models import Asset, AssetStatus, AssetType, JITAccessGrant, Tenant, User
from ..schemas import AssetCreate, AssetUpdate, JITActionRequest
from ..timeutils import now_iso, to_iso

router = APIRouter(prefix="/assets", tags=["assets"])


def _get_asset(db: Session, asset_id: int) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


def _authorize_asset(db: Session, user: User, asset: Asset, permission: str) -> None:
    enforce_tenant_membership(db, user, asset.tenant_id)
    enforce_permission(db, user, permission, asset.tenant_id)


@router.get("")
def list_assets(
    tenant_id: int | None = Query(default=None),
    status: AssetStatus | None = Query(default=None),
    asset_type: AssetType | None = Query(default=None, alias="type"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(Asset)

    if is_platform_admin(db, current_user):
        enforce_permission(db, current_user, "asset:read", tenant_id)
        if tenant_id is not None:
            query = query.filter(Asset.tenant_id == tenant_id)
    else:
        allowed = get_user_tenant_ids(db, current_user)
        if tenant_id is not None:
            enforce_tenant_membership(db, current_user, tenant_id)
            enforce_permission(db, current_user, "asset:read", tenant_id)
            allowed = [tenant_id]
        else:
            enforce_any_permission(db, current_user, "asset:read")
        if not allowed:
            return []
        query = query.filter(Asset.tenant_id.in_(allowed))

    if status is not None:
        query = query.filter(Asset.status == status.value)
    if asset_type is not None:
        query = query.filter(Asset.type == asset_type.value)
    return [asset_to_dict(row) for row in query.order_by(Asset.id).all()]


@router.post("", status_code=201)
def create_asset(
    payload: AssetCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if db.get(Tenant, payload.tenant_id) is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    enforce_tenant_membership(db, current_user, payload.tenant_id)
    enforce_permission(db, current_user, "asset:write", payload.tenant_id)

    if (
        db.query(Asset)
        .filter(Asset.tenant_id == payload.tenant_id, Asset.asset_tag == payload.asset_tag)
        .first()
    ):
        raise HTTPException(status_code=409, detail="asset_tag already exists in tenant")

    asset = Asset(
        tenant_id=payload.tenant_id,
        asset_tag=payload.asset_tag,
        name=payload.name,
        type=payload.type.value,
        site=payload.site,
        status=payload.status.value,
        last_seen=now_iso(),
        created_at=now_iso(),
    )
    db.add(asset)
    db.flush()
    write_audit(
        db,
        tenant_id=asset.tenant_id,
        actor_user_id=current_user.id,
        action="asset:create",
        target_type="asset",
        target_id=asset.id,
        details={"asset_tag": asset.asset_tag, "type": asset.type, "status": asset.status},
    )
    db.commit()
    return asset_to_dict(asset)


@router.get("/{asset_id}")
def get_asset(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    _authorize_asset(db, current_user, asset, "asset:read")
    return asset_to_dict(asset)


@router.patch("/{asset_id}")
def update_asset(
    asset_id: int,
    payload: AssetUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    _authorize_asset(db, current_user, asset, "asset:write")

    changes: dict = {}
    if payload.asset_tag is not None and payload.asset_tag != asset.asset_tag:
        clash = (
            db.query(Asset)
            .filter(
                Asset.tenant_id == asset.tenant_id,
                Asset.asset_tag == payload.asset_tag,
                Asset.id != asset.id,
            )
            .first()
        )
        if clash:
            raise HTTPException(status_code=409, detail="asset_tag already exists in tenant")
        asset.asset_tag = payload.asset_tag
        changes["asset_tag"] = payload.asset_tag
    if payload.name is not None:
        asset.name = payload.name
        changes["name"] = payload.name
    if payload.type is not None:
        asset.type = payload.type.value
        changes["type"] = asset.type
    if payload.site is not None:
        asset.site = payload.site
        changes["site"] = payload.site
    if payload.status is not None:
        asset.status = payload.status.value
        changes["status"] = asset.status
    if payload.last_seen is not None:
        asset.last_seen = to_iso(payload.last_seen)
        changes["last_seen"] = asset.last_seen

    if changes:
        write_audit(
            db,
            tenant_id=asset.tenant_id,
            actor_user_id=current_user.id,
            action="asset:update",
            target_type="asset",
            target_id=asset.id,
            details=changes,
        )
    db.commit()
    return asset_to_dict(asset)


@router.delete("/{asset_id}")
def delete_asset(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    _authorize_asset(db, current_user, asset, "asset:write")

    details = {"asset_tag": asset.asset_tag, "name": asset.name, "tenant_id": asset.tenant_id}
    db.delete(asset)
    write_audit(
        db,
        tenant_id=asset.tenant_id,
        actor_user_id=current_user.id,
        action="asset:delete",
        target_type="asset",
        target_id=asset_id,
        details=details,
    )
    db.commit()
    return {"detail": "Asset deleted", "id": asset_id}


@router.get("/{asset_id}/jit-active")
def list_asset_jit_grants(
    asset_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    enforce_tenant_membership(db, current_user, asset.tenant_id)
    enforce_permission(db, current_user, "jit:read", asset.tenant_id)

    expire_stale_grants(db, tenant_id=asset.tenant_id)
    db.commit()
    grants = (
        active_grants_query(db, tenant_id=asset.tenant_id)
        .filter(JITAccessGrant.asset_id == asset_id)
        .all()
    )
    return [jit_grant_to_dict(grant) for grant in grants]


@router.post("/{asset_id}/jit-action")
def use_jit_grant(
    asset_id: int,
    payload: JITActionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    asset = _get_asset(db, asset_id)
    enforce_tenant_membership(db, current_user, asset.tenant_id)
    enforce_permission(db, current_user, "asset:jit_access", asset.tenant_id)

    grant = active_grant_for_user_asset(
        db,
        user_id=current_user.id,
        tenant_id=asset.tenant_id,
        asset_id=asset.id,
        permission_code="asset:jit_access",
    )
    if grant is None:
        db.rollback()
        raise HTTPException(
            status_code=403,
            detail="No active JIT grant authorizes access to this asset",
        )

    write_audit(
        db,
        tenant_id=asset.tenant_id,
        actor_user_id=current_user.id,
        action="asset:jit_access",
        target_type="asset",
        target_id=asset.id,
        details={
            "grant_id": grant.id,
            "action": payload.action,
            "valid_until": grant.valid_until,
        },
    )
    db.commit()
    return {
        "detail": "Simulated OT action authorized by active JIT grant",
        "asset": asset_to_dict(asset),
        "grant": jit_grant_to_dict(grant),
        "action": payload.action,
        "executed_at": now_iso(),
    }
