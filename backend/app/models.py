"""SQLAlchemy ORM models for the BeeInControl simulator.

The schema follows ARCHITECTURE.md section 2.  Timestamps are stored as
canonical ISO-8601 UTC strings (``YYYY-MM-DDTHH:MM:SSZ``).
"""
from __future__ import annotations

from enum import Enum

from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from .database import Base
from .timeutils import now_iso


# ---------------------------------------------------------------------------
# Enumerations (kept as string enums so Pydantic/SQLite round-trip cleanly)
# ---------------------------------------------------------------------------
class Sector(str, Enum):
    energy = "energy"
    water = "water"
    transport = "transport"


class AssetType(str, Enum):
    PLC = "PLC"
    RTU = "RTU"
    HMI = "HMI"
    SENSOR = "SENSOR"
    CONTROLLER = "CONTROLLER"


class AssetStatus(str, Enum):
    online = "online"
    offline = "offline"
    maintenance = "maintenance"
    alert = "alert"


class JITStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    revoked = "revoked"
    expired = "expired"


class IncidentSeverity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IncidentStatus(str, Enum):
    open = "open"
    early_warning_sent = "early_warning_sent"
    notified_authority = "notified_authority"
    resolved = "resolved"
    closed = "closed"


class IncidentArticle(str, Enum):
    article_21 = "21"
    article_23 = "23"
    both = "both"


class RoleScope(str, Enum):
    tenant = "tenant"
    global_ = "global"


# ---------------------------------------------------------------------------
# Identity & tenancy
# ---------------------------------------------------------------------------
class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    slug = Column(String(120), nullable=False, unique=True)
    sector = Column(String(32), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(String(32), nullable=False, default=now_iso)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False, unique=True, index=True)
    full_name = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)
    # NULL = cross-tenant / platform user.
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True)
    is_vendor = Column(Boolean, nullable=False, default=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(String(32), nullable=False, default=now_iso)


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), nullable=False, unique=True)
    scope = Column(String(16), nullable=False, default=RoleScope.tenant.value)
    is_system = Column(Boolean, nullable=False, default=False)


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(String(64), nullable=False, unique=True)
    resource = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id = Column(Integer, ForeignKey("roles.id"), primary_key=True)
    permission_id = Column(Integer, ForeignKey("permissions.id"), primary_key=True)


class UserRole(Base):
    __tablename__ = "user_roles"
    __table_args__ = (
        UniqueConstraint("user_id", "role_id", "tenant_id", name="uq_user_role_tenant"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    # NULL is used only for global (platform_admin) assignments.
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    granted_at = Column(String(32), nullable=False, default=now_iso)
    expires_at = Column(String(32), nullable=True)


# ---------------------------------------------------------------------------
# OT fleet
# ---------------------------------------------------------------------------
class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "asset_tag", name="uq_asset_tenant_tag"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    asset_tag = Column(String(64), nullable=False)
    name = Column(String(255), nullable=False)
    type = Column(String(32), nullable=False)
    site = Column(String(255), nullable=True)
    status = Column(String(32), nullable=False, default=AssetStatus.offline.value)
    last_seen = Column(String(32), nullable=True)
    created_at = Column(String(32), nullable=False, default=now_iso)


# ---------------------------------------------------------------------------
# JIT vendor access
# ---------------------------------------------------------------------------
class JITAccessRequest(Base):
    __tablename__ = "jit_access_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    requesting_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    reason = Column(Text, nullable=False)
    requested_permissions = Column(Text, nullable=False)
    requested_until = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, default=JITStatus.pending.value)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(String(32), nullable=True)
    created_at = Column(String(32), nullable=False, default=now_iso)
    updated_at = Column(String(32), nullable=False, default=now_iso)


class JITAccessGrant(Base):
    __tablename__ = "jit_access_grants"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(Integer, ForeignKey("jit_access_requests.id"), nullable=False)
    grantee_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    granted_permissions = Column(Text, nullable=False)
    valid_from = Column(String(32), nullable=False)
    valid_until = Column(String(32), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    revoked_at = Column(String(32), nullable=True)
    revoked_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(String(32), nullable=False, default=now_iso)


# ---------------------------------------------------------------------------
# NIS2 incidents
# ---------------------------------------------------------------------------
class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, default=IncidentStatus.open.value)
    article = Column(String(16), nullable=False)
    declared_at = Column(String(32), nullable=False)
    early_warning_deadline = Column(String(32), nullable=False)
    notification_deadline = Column(String(32), nullable=False)
    early_warning_sent_at = Column(String(32), nullable=True)
    notification_sent_at = Column(String(32), nullable=True)
    resolved_at = Column(String(32), nullable=True)
    closed_at = Column(String(32), nullable=True)
    created_at = Column(String(32), nullable=False, default=now_iso)
    updated_at = Column(String(32), nullable=False, default=now_iso)


# ---------------------------------------------------------------------------
# Hash-chained audit log (append-only)
# ---------------------------------------------------------------------------
class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        UniqueConstraint("sequence_no", name="uq_audit_sequence"),
        Index("ix_audit_tenant_time", "tenant_id", "event_time"),
        Index("ix_audit_action", "action"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True)
    actor_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(96), nullable=False)
    target_type = Column(String(64), nullable=False)
    target_id = Column(String(64), nullable=False)
    details = Column(Text, nullable=False)
    event_time = Column(String(32), nullable=False)
    sequence_no = Column(Integer, nullable=False)
    previous_hash = Column(String(64), nullable=False)
    hash = Column(String(64), nullable=False)
    created_at = Column(String(32), nullable=False, default=now_iso)
