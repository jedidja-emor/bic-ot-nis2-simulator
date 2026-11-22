"""Tenant-scoped user management."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..auth import hash_password
from ..crud import user_to_dict
from ..database import get_db
from ..deps import (
    enforce_any_permission,
    enforce_permission,
    enforce_tenant_membership,
    get_current_user,
    get_user_tenant_ids,
    is_platform_admin,
)
from ..models import Role, Tenant, User, UserRole
from ..schemas import UserCreate, UserUpdate
from ..timeutils import now_iso

router = APIRouter(prefix="/users", tags=["users"])


def _user_roles(db: Session, user_id: int) -> list[dict]:
    rows = (
        db.query(Role.name, Role.scope, UserRole.tenant_id, UserRole.id, UserRole.expires_at)
        .join(UserRole, UserRole.role_id == Role.id)
        .filter(
            UserRole.user_id == user_id,
            or_(UserRole.expires_at.is_(None), UserRole.expires_at > now_iso()),
        )
        .all()
    )
    return [
        {
            "user_role_id": user_role_id,
            "name": name,
            "scope": scope,
            "tenant_id": tenant_id,
            "expires_at": expires_at,
        }
        for name, scope, tenant_id, user_role_id, expires_at in rows
    ]


def _serialize_user(db: Session, user: User) -> dict:
    data = user_to_dict(user)
    data["roles"] = _user_roles(db, user.id)
    return data


def _enforce_can_manage_user(db: Session, actor: User, target: User) -> None:
    if is_platform_admin(db, actor):
        enforce_permission(db, actor, "user:manage", None)
        return
    if target.tenant_id is None:
        raise HTTPException(status_code=403, detail="Cannot manage global users")
    enforce_tenant_membership(db, actor, target.tenant_id)
    enforce_permission(db, actor, "user:manage", target.tenant_id)


@router.get("")
def list_users(
    tenant_id: int | None = Query(default=None),
    include_inactive: bool = Query(default=False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(User)

    if is_platform_admin(db, current_user):
        enforce_permission(db, current_user, "user:manage", None)
        if tenant_id is not None:
            query = query.filter(User.tenant_id == tenant_id)
    else:
        allowed = get_user_tenant_ids(db, current_user)
        if tenant_id is not None:
            enforce_tenant_membership(db, current_user, tenant_id)
            enforce_permission(db, current_user, "user:manage", tenant_id)
            allowed = [tenant_id]
        else:
            enforce_any_permission(db, current_user, "user:manage")
        if not allowed:
            return []
        query = query.filter(User.tenant_id.in_(allowed))

    if not include_inactive:
        query = query.filter(User.is_active.is_(True))
    return [_serialize_user(db, row) for row in query.order_by(User.id).all()]


@router.post("", status_code=201)
def create_user(
    payload: UserCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    platform = is_platform_admin(db, current_user)

    if platform:
        enforce_permission(db, current_user, "user:manage", None)
        target_tenant_id = payload.tenant_id
    else:
        if payload.tenant_id is None:
            raise HTTPException(status_code=403, detail="Tenant users cannot create global users")
        enforce_tenant_membership(db, current_user, payload.tenant_id)
        enforce_permission(db, current_user, "user:manage", payload.tenant_id)
        target_tenant_id = payload.tenant_id

    if target_tenant_id is not None and db.get(Tenant, target_tenant_id) is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    email = payload.email.lower().strip()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail="Email already registered")

    role: Role | None = None
    if payload.role_id is not None:
        role = db.get(Role, payload.role_id)
        if role is None:
            raise HTTPException(status_code=404, detail="Role not found")
        if role.scope == "global":
            if not platform:
                raise HTTPException(status_code=403, detail="Only platform admins may assign global roles")
            if target_tenant_id is not None:
                raise HTTPException(
                    status_code=400,
                    detail="Global roles require a global (tenant-less) user",
                )
        elif target_tenant_id is None:
            raise HTTPException(status_code=400, detail="Tenant roles require a tenant_id")

    user = User(
        email=email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        tenant_id=target_tenant_id,
        is_vendor=payload.is_vendor,
        is_active=payload.is_active,
        created_at=now_iso(),
    )
    db.add(user)
    db.flush()

    if role is not None:
        assignment_tenant = None if role.scope == "global" else target_tenant_id
        db.add(
            UserRole(
                user_id=user.id,
                role_id=role.id,
                tenant_id=assignment_tenant,
                granted_by=current_user.id,
                granted_at=now_iso(),
            )
        )

    write_audit(
        db,
        tenant_id=target_tenant_id,
        actor_user_id=current_user.id,
        action="user:create",
        target_type="user",
        target_id=user.id,
        details={
            "email": user.email,
            "tenant_id": target_tenant_id,
            "is_vendor": bool(user.is_vendor),
            "role_id": payload.role_id,
        },
    )
    db.commit()
    return _serialize_user(db, user)


@router.get("/{user_id}")
def get_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    _enforce_can_manage_user(db, current_user, user)
    return _serialize_user(db, user)


@router.patch("/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    _enforce_can_manage_user(db, current_user, user)

    changes: dict = {}
    if payload.full_name is not None:
        user.full_name = payload.full_name
        changes["full_name"] = payload.full_name
    if payload.is_active is not None:
        user.is_active = payload.is_active
        changes["is_active"] = bool(payload.is_active)
    if payload.is_vendor is not None:
        user.is_vendor = payload.is_vendor
        changes["is_vendor"] = bool(payload.is_vendor)
    if payload.password is not None:
        user.password_hash = hash_password(payload.password)
        changes["password_reset"] = True

    if changes:
        write_audit(
            db,
            tenant_id=user.tenant_id,
            actor_user_id=current_user.id,
            action="user:update",
            target_type="user",
            target_id=user.id,
            details=changes,
        )
    db.commit()
    return _serialize_user(db, user)


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    _enforce_can_manage_user(db, current_user, user)
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    user.is_active = False
    write_audit(
        db,
        tenant_id=user.tenant_id,
        actor_user_id=current_user.id,
        action="user:delete",
        target_type="user",
        target_id=user.id,
        details={"soft_delete": True, "email": user.email},
    )
    db.commit()
    return {"detail": "User deactivated", "id": user.id}
