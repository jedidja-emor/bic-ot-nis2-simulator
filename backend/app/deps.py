"""FastAPI dependencies and tenant-scoped RBAC enforcement helpers."""
from __future__ import annotations

from datetime import datetime, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .auth import decode_access_token
from .database import get_db
from .models import Permission, Role, RolePermission, User, UserRole
from .timeutils import now_iso, parse_iso

bearer_scheme = HTTPBearer(auto_error=False)


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_token_payload(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()
    try:
        return decode_access_token(credentials.credentials)
    except jwt.ExpiredSignatureError as exc:
        raise _unauthorized("Token has expired") from exc
    except jwt.PyJWTError as exc:
        raise _unauthorized("Invalid token") from exc


def get_current_user(
    payload: dict = Depends(get_token_payload),
    db: Session = Depends(get_db),
) -> User:
    try:
        user_id = int(payload.get("sub", ""))
    except (TypeError, ValueError) as exc:
        raise _unauthorized("Invalid token subject") from exc

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _unauthorized("User not found or inactive")
    return user


# ---------------------------------------------------------------------------
# Role / permission helpers
# ---------------------------------------------------------------------------
def is_platform_admin(db: Session, user: User) -> bool:
    if user.tenant_id is not None:
        return False
    row = (
        db.query(Role.id)
        .join(UserRole, UserRole.role_id == Role.id)
        .filter(
            UserRole.user_id == user.id,
            Role.scope == "global",
            Role.name == "platform_admin",
        )
        .first()
    )
    return row is not None


def _active_grant_filter():
    return or_(UserRole.expires_at.is_(None), UserRole.expires_at > now_iso())


def get_user_role_names(db: Session, user: User, tenant_id: int | None = None) -> list[str]:
    query = (
        db.query(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .filter(UserRole.user_id == user.id, _active_grant_filter())
    )
    if tenant_id is None:
        query = query.filter(UserRole.tenant_id.is_(None))
    else:
        query = query.filter(UserRole.tenant_id == tenant_id)
    return [row[0] for row in query.all()]


def get_user_tenant_ids(db: Session, user: User) -> list[int]:
    if is_platform_admin(db, user):
        return []
    rows = (
        db.query(UserRole.tenant_id)
        .filter(
            UserRole.user_id == user.id,
            UserRole.tenant_id.is_not(None),
            _active_grant_filter(),
        )
        .distinct()
        .all()
    )
    return sorted({int(row[0]) for row in rows if row[0] is not None})


def get_permission_codes(db: Session, user: User, tenant_id: int | None) -> set[str]:
    """Permission codes held by ``user`` in the given tenant context.

    Platform admins hold every permission globally.  A ``tenant_id`` of
    ``None`` for a normal user returns their global role permissions only.
    """
    if is_platform_admin(db, user):
        return {row[0] for row in db.query(Permission.code).all()}

    query = (
        db.query(Permission.code)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .filter(UserRole.user_id == user.id, _active_grant_filter())
    )
    if tenant_id is None:
        query = query.filter(UserRole.tenant_id.is_(None))
    else:
        query = query.filter(UserRole.tenant_id == tenant_id)
    return {row[0] for row in query.all()}


def has_permission(db: Session, user: User, permission_code: str, tenant_id: int | None) -> bool:
    return permission_code in get_permission_codes(db, user, tenant_id)


def has_permission_any(db: Session, user: User, permission_code: str) -> bool:
    if is_platform_admin(db, user):
        return True
    for tenant_id in get_user_tenant_ids(db, user):
        if has_permission(db, user, permission_code, tenant_id):
            return True
    return has_permission(db, user, permission_code, None)


def enforce_permission(
    db: Session,
    user: User,
    permission_code: str,
    tenant_id: int | None,
) -> None:
    if not has_permission(db, user, permission_code, tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required permission '{permission_code}' for tenant {tenant_id}",
        )


def enforce_any_permission(db: Session, user: User, permission_code: str) -> None:
    if not has_permission_any(db, user, permission_code):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing required permission '{permission_code}'",
        )


def is_tenant_member(db: Session, user: User, tenant_id: int) -> bool:
    if is_platform_admin(db, user):
        return True
    row = (
        db.query(UserRole.id)
        .filter(
            UserRole.user_id == user.id,
            UserRole.tenant_id == tenant_id,
            _active_grant_filter(),
        )
        .first()
    )
    return row is not None


def enforce_tenant_membership(db: Session, user: User, tenant_id: int) -> None:
    if not is_tenant_member(db, user, tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cross-tenant access denied for tenant {tenant_id}",
        )


def require_permission(permission_code: str, tenant_query_param: str = "tenant_id"):
    """Dependency factory for endpoints that carry ``?tenant_id=``.

    Resource-specific routes additionally call :func:`enforce_permission` with
    the owning tenant of the resource.
    """

    def dependency(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        raw = request.query_params.get(tenant_query_param)
        if raw not in (None, ""):
            try:
                tenant_id = int(raw)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="tenant_id must be an integer") from exc
            enforce_permission(db, current_user, permission_code, tenant_id)
        else:
            enforce_any_permission(db, current_user, permission_code)
        return current_user

    return dependency


def parse_datetime(value: str | datetime | None) -> datetime | None:
    return parse_iso(value)


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)
