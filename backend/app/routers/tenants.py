"""Tenant management endpoints (platform-scoped)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..crud import tenant_to_dict
from ..database import get_db
from ..deps import (
    enforce_permission,
    enforce_tenant_membership,
    get_current_user,
    get_user_tenant_ids,
    is_platform_admin,
)
from ..models import Tenant, User
from ..schemas import TenantCreate, TenantUpdate
from ..timeutils import now_iso

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.get("")
def list_tenants(
    include_inactive: bool = Query(default=False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if is_platform_admin(db, current_user):
        enforce_permission(db, current_user, "tenant:manage", None)
        query = db.query(Tenant)
        if not include_inactive:
            query = query.filter(Tenant.is_active.is_(True))
        return [tenant_to_dict(row) for row in query.order_by(Tenant.id).all()]

    tenant_ids = get_user_tenant_ids(db, current_user)
    if not tenant_ids:
        return []
    query = db.query(Tenant).filter(Tenant.id.in_(tenant_ids))
    if not include_inactive:
        query = query.filter(Tenant.is_active.is_(True))
    return [tenant_to_dict(row) for row in query.order_by(Tenant.id).all()]


@router.post("", status_code=201)
def create_tenant(
    payload: TenantCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce_permission(db, current_user, "tenant:manage", None)
    if not is_platform_admin(db, current_user):
        raise HTTPException(status_code=403, detail="Only platform admins may create tenants")

    if db.query(Tenant).filter(Tenant.slug == payload.slug).first():
        raise HTTPException(status_code=409, detail="Tenant slug already exists")
    if db.query(Tenant).filter(Tenant.name == payload.name).first():
        raise HTTPException(status_code=409, detail="Tenant name already exists")

    tenant = Tenant(
        name=payload.name,
        slug=payload.slug,
        sector=payload.sector.value,
        is_active=payload.is_active,
        created_at=now_iso(),
    )
    db.add(tenant)
    db.flush()
    write_audit(
        db,
        tenant_id=tenant.id,
        actor_user_id=current_user.id,
        action="tenant:create",
        target_type="tenant",
        target_id=tenant.id,
        details={"name": tenant.name, "slug": tenant.slug, "sector": tenant.sector},
    )
    db.commit()
    return tenant_to_dict(tenant)


@router.get("/{tenant_id}")
def get_tenant(
    tenant_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    if not is_platform_admin(db, current_user):
        enforce_tenant_membership(db, current_user, tenant_id)
    return tenant_to_dict(tenant)


@router.patch("/{tenant_id}")
def update_tenant(
    tenant_id: int,
    payload: TenantUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce_permission(db, current_user, "tenant:manage", None)
    if not is_platform_admin(db, current_user):
        raise HTTPException(status_code=403, detail="Only platform admins may update tenants")

    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    changes: dict = {}
    if payload.name is not None and payload.name != tenant.name:
        clash = db.query(Tenant).filter(Tenant.name == payload.name, Tenant.id != tenant.id).first()
        if clash:
            raise HTTPException(status_code=409, detail="Tenant name already exists")
        tenant.name = payload.name
        changes["name"] = payload.name
    if payload.sector is not None:
        tenant.sector = payload.sector.value
        changes["sector"] = tenant.sector
    if payload.is_active is not None:
        tenant.is_active = payload.is_active
        changes["is_active"] = bool(payload.is_active)

    if changes:
        write_audit(
            db,
            tenant_id=tenant.id,
            actor_user_id=current_user.id,
            action="tenant:update",
            target_type="tenant",
            target_id=tenant.id,
            details=changes,
        )
    db.commit()
    return tenant_to_dict(tenant)
