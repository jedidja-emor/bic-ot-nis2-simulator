"""Roles, permissions and tenant-scoped role assignments."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..crud import permission_to_dict, role_to_dict
from ..database import get_db
from ..deps import (
    enforce_any_permission,
    enforce_permission,
    enforce_tenant_membership,
    get_current_user,
    get_user_tenant_ids,
    is_platform_admin,
)
from ..models import Permission, Role, RolePermission, Tenant, User, UserRole
from ..schemas import RoleCreate, UserRoleCreate
from ..timeutils import now_iso, parse_iso, to_iso

router = APIRouter(tags=["roles"])


def _role_permission_codes(db: Session, role_id: int) -> list[str]:
    rows = (
        db.query(Permission.code)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .filter(RolePermission.role_id == role_id)
        .all()
    )
    return sorted({row[0] for row in rows})


@router.get("/roles")
def list_roles(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Both role administrators and user managers need the role catalogue.
    if not (
        "role:manage" in _any_codes(db, current_user)
        or "user:manage" in _any_codes(db, current_user)
    ):
        enforce_any_permission(db, current_user, "role:manage")
    rows = db.query(Role).order_by(Role.id).all()
    return [role_to_dict(row, _role_permission_codes(db, row.id)) for row in rows]


def _any_codes(db: Session, user: User) -> set[str]:
    from ..deps import get_permission_codes

    codes: set[str] = set()
    if is_platform_admin(db, user):
        codes.update(get_permission_codes(db, user, None))
        return codes
    for tenant_id in get_user_tenant_ids(db, user):
        codes.update(get_permission_codes(db, user, tenant_id))
    codes.update(get_permission_codes(db, user, None))
    return codes


@router.post("/roles", status_code=201)
def create_role(
    payload: RoleCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    enforce_any_permission(db, current_user, "role:manage")
    if db.query(Role).filter(Role.name == payload.name).first():
        raise HTTPException(status_code=409, detail="Role name already exists")

    permissions = []
    for code in payload.permission_codes:
        perm = db.query(Permission).filter(Permission.code == code).first()
        if perm is None:
            raise HTTPException(status_code=400, detail=f"Unknown permission code: {code}")
        permissions.append(perm)

    role = Role(name=payload.name, scope=payload.scope.value, is_system=False)
    db.add(role)
    db.flush()
    for perm in permissions:
        db.add(RolePermission(role_id=role.id, permission_id=perm.id))

    write_audit(
        db,
        tenant_id=None,
        actor_user_id=current_user.id,
        action="role:create",
        target_type="role",
        target_id=role.id,
        details={"name": role.name, "scope": role.scope, "permissions": sorted(payload.permission_codes)},
    )
    db.commit()
    return role_to_dict(role, _role_permission_codes(db, role.id))


@router.get("/permissions")
def list_permissions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    codes = _any_codes(db, current_user)
    if "role:manage" not in codes and "user:manage" not in codes:
        enforce_any_permission(db, current_user, "role:manage")
    return [permission_to_dict(row) for row in db.query(Permission).order_by(Permission.id).all()]


@router.post("/user-roles", status_code=201)
def assign_role(
    payload: UserRoleCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    platform = is_platform_admin(db, current_user)

    target_user = db.get(User, payload.user_id)
    if target_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    role = db.get(Role, payload.role_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found")

    if role.scope == "global":
        if not platform:
            raise HTTPException(status_code=403, detail="Only platform admins may assign global roles")
        if payload.tenant_id is not None:
            raise HTTPException(status_code=400, detail="Global roles must not carry a tenant_id")
        if target_user.tenant_id is not None:
            raise HTTPException(status_code=400, detail="Global roles require a global (tenant-less) user")
        tenant_id = None
    else:
        if payload.tenant_id is None:
            raise HTTPException(status_code=400, detail="Tenant roles require a tenant_id")
        tenant_id = payload.tenant_id
        if db.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=404, detail="Tenant not found")
        if not platform:
            enforce_tenant_membership(db, current_user, tenant_id)
            enforce_permission(db, current_user, "user:manage", tenant_id)
            if target_user.tenant_id != tenant_id:
                raise HTTPException(status_code=403, detail="Cross-tenant user assignment denied")
        else:
            enforce_permission(db, current_user, "user:manage", None)

    if not platform and target_user.tenant_id is None:
        raise HTTPException(status_code=403, detail="Cannot manage global users")

    expires_at = None
    if payload.expires_at is not None:
        parsed = parse_iso(payload.expires_at)
        if parsed is not None and parsed <= parse_iso(now_iso()):
            raise HTTPException(status_code=400, detail="expires_at must be in the future")
        expires_at = to_iso(parsed)

    existing = (
        db.query(UserRole)
        .filter(
            UserRole.user_id == target_user.id,
            UserRole.role_id == role.id,
            UserRole.tenant_id == tenant_id if tenant_id is not None else UserRole.tenant_id.is_(None),
        )
        .first()
    )
    if existing is not None:
        still_active = existing.expires_at is None or existing.expires_at > now_iso()
        if still_active:
            raise HTTPException(status_code=409, detail="User already has this role in the tenant")
        # Re-activate an elapsed assignment instead of creating a duplicate.
        existing.granted_by = current_user.id
        existing.granted_at = now_iso()
        existing.expires_at = expires_at
        assignment = existing
    else:
        assignment = UserRole(
            user_id=target_user.id,
            role_id=role.id,
            tenant_id=tenant_id,
            granted_by=current_user.id,
            granted_at=now_iso(),
            expires_at=expires_at,
        )
        db.add(assignment)
    db.flush()
    write_audit(
        db,
        tenant_id=tenant_id,
        actor_user_id=current_user.id,
        action="role:assign",
        target_type="user_role",
        target_id=assignment.id,
        details={"user_id": target_user.id, "role": role.name, "tenant_id": tenant_id},
    )
    db.commit()
    return {
        "id": assignment.id,
        "user_id": assignment.user_id,
        "role_id": assignment.role_id,
        "role": role.name,
        "tenant_id": assignment.tenant_id,
        "granted_by": assignment.granted_by,
        "granted_at": assignment.granted_at,
        "expires_at": assignment.expires_at,
    }


@router.delete("/user-roles/{assignment_id}")
def remove_role(
    assignment_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    assignment = db.get(UserRole, assignment_id)
    if assignment is None:
        raise HTTPException(status_code=404, detail="Role assignment not found")

    if is_platform_admin(db, current_user):
        enforce_permission(db, current_user, "user:manage", None)
    else:
        if assignment.tenant_id is None:
            raise HTTPException(status_code=403, detail="Cannot manage global assignments")
        enforce_tenant_membership(db, current_user, assignment.tenant_id)
        enforce_permission(db, current_user, "user:manage", assignment.tenant_id)

    role = db.get(Role, assignment.role_id)
    details = {
        "user_id": assignment.user_id,
        "role_id": assignment.role_id,
        "role": role.name if role else None,
        "tenant_id": assignment.tenant_id,
    }
    db.delete(assignment)
    write_audit(
        db,
        tenant_id=assignment.tenant_id,
        actor_user_id=current_user.id,
        action="role:remove",
        target_type="user_role",
        target_id=assignment_id,
        details=details,
    )
    db.commit()
    return {"detail": "Role assignment removed", "id": assignment_id}
