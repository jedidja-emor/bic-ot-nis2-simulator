"""Authentication endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..auth import authenticate_user, create_access_token, revoke_token
from ..crud import tenant_to_dict, user_to_dict
from ..database import get_db
from ..deps import (
    get_current_user,
    get_permission_codes,
    get_token_payload,
    get_user_tenant_ids,
    is_platform_admin,
)
from ..models import Role, Tenant, User, UserRole
from ..schemas import LoginRequest, TokenResponse
from ..timeutils import now_iso

router = APIRouter(prefix="/auth", tags=["auth"])


def build_user_context(db: Session, user: User) -> dict:
    platform = is_platform_admin(db, user)
    if platform:
        tenant_ids = [row[0] for row in db.query(Tenant.id).order_by(Tenant.id).all()]
    else:
        tenant_ids = get_user_tenant_ids(db, user)

    role_rows = (
        db.query(Role.name, Role.scope, UserRole.tenant_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .filter(
            UserRole.user_id == user.id,
            or_(UserRole.expires_at.is_(None), UserRole.expires_at > now_iso()),
        )
        .all()
    )
    roles = [
        {"name": name, "scope": scope, "tenant_id": tenant_id}
        for name, scope, tenant_id in role_rows
    ]

    permissions: dict[str, list[str]] = {}
    for tenant_id in tenant_ids:
        permissions[str(tenant_id)] = sorted(get_permission_codes(db, user, tenant_id))
    if platform:
        permissions["global"] = sorted(get_permission_codes(db, user, None))

    union: set[str] = set()
    for codes in permissions.values():
        union.update(codes)

    tenants = []
    for tenant_id in tenant_ids:
        tenant = db.get(Tenant, tenant_id)
        if tenant is not None:
            tenants.append(tenant_to_dict(tenant))

    user_data = user_to_dict(user)
    context = {
        "user": user_data,
        "is_platform_admin": platform,
        "tenant_ids": tenant_ids,
        "tenants": tenants,
        "roles": roles,
        "permissions": permissions,
        "permission_codes": sorted(union),
    }
    # Expose the user's own fields at the top level as well, so the login
    # response is convenient for both ``data.user.email`` and ``data.email``.
    context.update(user_data)
    return context


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, payload.email, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    token, _ = create_access_token(user)
    write_audit(
        db,
        tenant_id=user.tenant_id,
        actor_user_id=user.id,
        action="auth:login",
        target_type="user",
        target_id=user.id,
        details={"email": user.email},
        event_time=now_iso(),
    )
    db.commit()
    return {"access_token": token, "token_type": "bearer", "user": build_user_context(db, user)}


@router.post("/logout")
def logout(
    payload: dict = Depends(get_token_payload),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    revoke_token(payload)
    write_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="auth:logout",
        target_type="user",
        target_id=current_user.id,
        details={"jti": payload.get("jti")},
        event_time=now_iso(),
    )
    db.commit()
    return {"detail": "Logged out"}


@router.get("/me")
def me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return build_user_context(db, current_user)
