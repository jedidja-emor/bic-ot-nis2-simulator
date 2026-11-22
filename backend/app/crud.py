"""Small DB/serialization helpers shared by routers."""
from __future__ import annotations

import json
from typing import Any, Iterable

from sqlalchemy.orm import Session

from .models import (
    Asset,
    Incident,
    JITAccessGrant,
    JITAccessRequest,
    Permission,
    Role,
    Tenant,
    User,
)


def split_permissions(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def join_permissions(values: Iterable[str]) -> str:
    # Stable ordering keeps audit details deterministic.
    return ",".join(sorted({value.strip() for value in values if value and value.strip()}))


def tenant_to_dict(row: Tenant) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "slug": row.slug,
        "sector": row.sector,
        "is_active": bool(row.is_active),
        "created_at": row.created_at,
    }


def user_to_dict(row: User) -> dict[str, Any]:
    # password_hash is deliberately never serialized.
    return {
        "id": row.id,
        "email": row.email,
        "full_name": row.full_name,
        "tenant_id": row.tenant_id,
        "is_vendor": bool(row.is_vendor),
        "is_active": bool(row.is_active),
        "created_at": row.created_at,
    }


def role_to_dict(row: Role, permission_codes: list[str] | None = None) -> dict[str, Any]:
    data = {
        "id": row.id,
        "name": row.name,
        "scope": row.scope,
        "is_system": bool(row.is_system),
    }
    if permission_codes is not None:
        data["permissions"] = sorted(permission_codes)
    return data


def permission_to_dict(row: Permission) -> dict[str, Any]:
    return {
        "id": row.id,
        "code": row.code,
        "resource": row.resource,
        "action": row.action,
    }


def asset_to_dict(row: Asset) -> dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "asset_tag": row.asset_tag,
        "name": row.name,
        "type": row.type,
        "site": row.site,
        "status": row.status,
        "last_seen": row.last_seen,
        "created_at": row.created_at,
    }


def jit_request_to_dict(row: JITAccessRequest) -> dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "requesting_user_id": row.requesting_user_id,
        "asset_id": row.asset_id,
        "reason": row.reason,
        "requested_permissions": split_permissions(row.requested_permissions),
        "requested_until": row.requested_until,
        "status": row.status,
        "approved_by": row.approved_by,
        "approved_at": row.approved_at,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def jit_grant_to_dict(row: JITAccessGrant) -> dict[str, Any]:
    return {
        "id": row.id,
        "request_id": row.request_id,
        "grantee_user_id": row.grantee_user_id,
        "asset_id": row.asset_id,
        "granted_permissions": split_permissions(row.granted_permissions),
        "valid_from": row.valid_from,
        "valid_until": row.valid_until,
        "is_active": bool(row.is_active),
        "revoked_at": row.revoked_at,
        "revoked_by": row.revoked_by,
        "created_at": row.created_at,
    }


def incident_to_dict(row: Incident) -> dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "title": row.title,
        "description": row.description,
        "severity": row.severity,
        "status": row.status,
        "article": row.article,
        "declared_at": row.declared_at,
        "early_warning_deadline": row.early_warning_deadline,
        "notification_deadline": row.notification_deadline,
        "early_warning_sent_at": row.early_warning_sent_at,
        "notification_sent_at": row.notification_sent_at,
        "resolved_at": row.resolved_at,
        "closed_at": row.closed_at,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def load_details(raw: str) -> Any:
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return raw


def get_role_permission_codes(db: Session, role_id: int) -> list[str]:
    from .models import RolePermission

    rows = (
        db.query(Permission.code)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .filter(RolePermission.role_id == role_id)
        .all()
    )
    return sorted({row[0] for row in rows})
