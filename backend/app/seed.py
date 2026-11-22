"""Deterministic demo seed data: 3 industrial tenants, RBAC, users and assets."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from .audit import write_audit
from .auth import hash_password
from .models import (
    Asset,
    Permission,
    Role,
    RolePermission,
    Tenant,
    User,
    UserRole,
)
from .timeutils import now_iso

PERMISSIONS: list[tuple[str, str, str]] = [
    ("asset:read", "asset", "read"),
    ("asset:write", "asset", "write"),
    ("asset:jit_access", "asset", "jit_access"),
    ("incident:read", "incident", "read"),
    ("incident:declare", "incident", "declare"),
    ("incident:early_warning", "incident", "early_warning"),
    ("incident:notify", "incident", "notify"),
    ("jit:request", "jit", "request"),
    ("jit:approve", "jit", "approve"),
    ("jit:read", "jit", "read"),
    ("user:manage", "user", "manage"),
    ("role:manage", "role", "manage"),
    ("tenant:manage", "tenant", "manage"),
    ("audit:read", "audit", "read"),
]

ROLE_DEFINITIONS: dict[str, dict[str, Any]] = {
    "tenant_admin": {
        "scope": "tenant",
        "permissions": [
            "user:manage",
            "asset:read",
            "asset:write",
            "asset:jit_access",
            "incident:read",
            "incident:declare",
            "incident:early_warning",
            "incident:notify",
            "jit:request",
            "jit:approve",
            "jit:read",
            "audit:read",
        ],
    },
    "site_engineer": {
        "scope": "tenant",
        "permissions": ["asset:read", "asset:write", "incident:read"],
    },
    "viewer": {
        "scope": "tenant",
        "permissions": ["asset:read", "incident:read", "audit:read"],
    },
    "security_officer": {
        "scope": "tenant",
        "permissions": [
            "incident:read",
            "incident:declare",
            "incident:early_warning",
            "incident:notify",
            "audit:read",
            "jit:read",
        ],
    },
    "vendor_remote": {
        "scope": "tenant",
        "permissions": [
            "asset:read",
            "asset:jit_access",
            "jit:request",
            "jit:read",
        ],
    },
    "platform_admin": {
        "scope": "global",
        "permissions": [code for code, _, _ in PERMISSIONS],
    },
}

TENANTS = [
    {"name": "NorthGrid Energy", "slug": "northgrid", "sector": "energy"},
    {"name": "AquaFlow Utilities", "slug": "aquaflow", "sector": "water"},
    {"name": "TransitRail Systems", "slug": "transitrail", "sector": "transport"},
]

# (email, full_name, password, tenant_slug | None, is_vendor, role)
USERS = [
    ("platform@beeincontrol.io", "Platform Administrator", "Platform123!", None, False, "platform_admin"),
    ("admin@northgrid.io", "Nora Grid Admin", "NorthGrid123!", "northgrid", False, "tenant_admin"),
    ("engineer@northgrid.io", "Eli Engineer", "NorthGrid123!", "northgrid", False, "site_engineer"),
    ("officer@northgrid.io", "Olga Security", "NorthGrid123!", "northgrid", False, "security_officer"),
    ("viewer@northgrid.io", "Vera Viewer", "NorthGrid123!", "northgrid", False, "viewer"),
    ("vendor@acme-ot.com", "Vic Vendor", "Vendor123!", "northgrid", True, "vendor_remote"),
    ("admin@aquaflow.io", "Avery Aqua Admin", "AquaFlow123!", "aquaflow", False, "tenant_admin"),
    ("officer@aquaflow.io", "Oscar Water Security", "AquaFlow123!", "aquaflow", False, "security_officer"),
    ("vendor@aqua-ot.com", "Val Water Vendor", "Vendor123!", "aquaflow", True, "vendor_remote"),
    ("admin@transitrail.io", "Tara Transit Admin", "TransitRail123!", "transitrail", False, "tenant_admin"),
    ("engineer@transitrail.io", "Tomas Track Engineer", "TransitRail123!", "transitrail", False, "site_engineer"),
    ("vendor@rail-ot.com", "Ravi Rail Vendor", "Vendor123!", "transitrail", True, "vendor_remote"),
]

ASSETS = [
    # NorthGrid Energy
    ("northgrid", "PLC-001", "Substation PLC A", "PLC", "North Substation", "online"),
    ("northgrid", "RTU-001", "Feeder RTU", "RTU", "East Feeder", "online"),
    ("northgrid", "HMI-001", "Control Room HMI", "HMI", "Control Center", "maintenance"),
    ("northgrid", "SENSOR-001", "Transformer Temp Sensor", "SENSOR", "North Substation", "alert"),
    # AquaFlow Utilities
    ("aquaflow", "PLC-101", "Pump Station PLC", "PLC", "River Pump Station", "online"),
    ("aquaflow", "RTU-101", "Reservoir RTU", "RTU", "Hill Reservoir", "offline"),
    ("aquaflow", "SENSOR-101", "Chlorine Sensor", "SENSOR", "Treatment Plant", "online"),
    # TransitRail Systems
    ("transitrail", "CONTROLLER-201", "Signal Controller", "CONTROLLER", "Central Junction", "online"),
    ("transitrail", "PLC-201", "Track Switch PLC", "PLC", "West Yard", "maintenance"),
    ("transitrail", "HMI-201", "Dispatch HMI", "HMI", "Operations Center", "online"),
]


def _ensure_rbac(db: Session) -> dict[str, Role]:
    permission_by_code: dict[str, Permission] = {}
    for code, resource, action in PERMISSIONS:
        perm = db.query(Permission).filter(Permission.code == code).first()
        if perm is None:
            perm = Permission(code=code, resource=resource, action=action)
            db.add(perm)
            db.flush()
        permission_by_code[code] = perm

    roles: dict[str, Role] = {}
    for name, definition in ROLE_DEFINITIONS.items():
        role = db.query(Role).filter(Role.name == name).first()
        if role is None:
            role = Role(name=name, scope=definition["scope"], is_system=True)
            db.add(role)
            db.flush()
        roles[name] = role
        existing = {
            row[0]
            for row in db.query(RolePermission.permission_id)
            .filter(RolePermission.role_id == role.id)
            .all()
        }
        for code in definition["permissions"]:
            perm = permission_by_code[code]
            if perm.id not in existing:
                db.add(RolePermission(role_id=role.id, permission_id=perm.id))
    db.flush()
    return roles


def _counts(db: Session) -> dict[str, int]:
    return {
        "tenants": db.query(Tenant).count(),
        "users": db.query(User).count(),
        "assets": db.query(Asset).count(),
    }


def seed_database(db: Session) -> dict[str, Any]:
    """Seed the simulator. Idempotent: existing tenants are not duplicated."""
    roles = _ensure_rbac(db)

    existing_tenants = db.query(Tenant).count()
    if existing_tenants:
        db.commit()
        return {
            "seeded": False,
            "message": "Database already contains tenants; seed skipped.",
            "counts": _counts(db),
        }

    tenants_by_slug: dict[str, Tenant] = {}
    for data in TENANTS:
        tenant = Tenant(
            name=data["name"],
            slug=data["slug"],
            sector=data["sector"],
            is_active=True,
            created_at=now_iso(),
        )
        db.add(tenant)
        db.flush()
        tenants_by_slug[tenant.slug] = tenant

    users_by_email: dict[str, User] = {}
    for email, full_name, password, tenant_slug, is_vendor, role_name in USERS:
        tenant_id = tenants_by_slug[tenant_slug].id if tenant_slug else None
        user = User(
            email=email,
            full_name=full_name,
            password_hash=hash_password(password),
            tenant_id=tenant_id,
            is_vendor=is_vendor,
            is_active=True,
            created_at=now_iso(),
        )
        db.add(user)
        db.flush()
        users_by_email[email] = user

        role = roles[role_name]
        db.add(
            UserRole(
                user_id=user.id,
                role_id=role.id,
                tenant_id=tenant_id,
                granted_by=None,
                granted_at=now_iso(),
                expires_at=None,
            )
        )

    now = now_iso()
    for tenant_slug, tag, name, asset_type, site, asset_status in ASSETS:
        db.add(
            Asset(
                tenant_id=tenants_by_slug[tenant_slug].id,
                asset_tag=tag,
                name=name,
                type=asset_type,
                site=site,
                status=asset_status,
                last_seen=now,
                created_at=now,
            )
        )

    platform = users_by_email["platform@beeincontrol.io"]
    write_audit(
        db,
        tenant_id=None,
        actor_user_id=platform.id,
        action="system:seed",
        target_type="system",
        target_id="seed",
        details={
            "tenants": [t["slug"] for t in TENANTS],
            "users": len(USERS),
            "assets": len(ASSETS),
        },
    )
    db.commit()

    return {
        "seeded": True,
        "message": "Seeded 3 industrial tenants, demo users/roles and OT assets.",
        "counts": _counts(db),
    }
