"""Pydantic v2 request/response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .models import (
    AssetStatus,
    AssetType,
    IncidentArticle,
    IncidentSeverity,
    IncidentStatus,
    RoleScope,
    Sector,
)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict[str, Any]


# ---------------------------------------------------------------------------
# Tenants
# ---------------------------------------------------------------------------
class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    slug: str = Field(min_length=2, max_length=120, pattern=r"^[a-z0-9-]+$")
    sector: Sector
    is_active: bool = True


class TenantUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=255)
    sector: Sector | None = None
    is_active: bool | None = None


# ---------------------------------------------------------------------------
# Users / roles
# ---------------------------------------------------------------------------
class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=6, max_length=256)
    tenant_id: int | None = None
    is_vendor: bool = False
    is_active: bool = True
    role_id: int | None = None


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=255)
    is_active: bool | None = None
    is_vendor: bool | None = None
    password: str | None = Field(default=None, min_length=6, max_length=256)


class RoleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=64)
    scope: RoleScope = RoleScope.tenant
    permission_codes: list[str] = Field(default_factory=list)


class UserRoleCreate(BaseModel):
    user_id: int
    role_id: int
    tenant_id: int | None = None
    expires_at: datetime | None = None


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------
class AssetCreate(BaseModel):
    tenant_id: int
    asset_tag: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=255)
    type: AssetType
    site: str | None = Field(default=None, max_length=255)
    status: AssetStatus = AssetStatus.offline


class AssetUpdate(BaseModel):
    asset_tag: str | None = Field(default=None, min_length=1, max_length=64)
    name: str | None = Field(default=None, min_length=1, max_length=255)
    type: AssetType | None = None
    site: str | None = Field(default=None, max_length=255)
    status: AssetStatus | None = None
    last_seen: datetime | None = None


class JITActionRequest(BaseModel):
    action: str = Field(default="simulated_ot_action", max_length=128)


# ---------------------------------------------------------------------------
# JIT access
# ---------------------------------------------------------------------------
class JITRequestCreate(BaseModel):
    tenant_id: int
    asset_id: int | None = None
    reason: str = Field(min_length=3, max_length=2000)
    requested_permissions: str
    requested_until: datetime

    @field_validator("requested_permissions", mode="before")
    @classmethod
    def _join_permissions(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple, set)):
            return ",".join(str(item) for item in value)
        return value

    @field_validator("requested_permissions")
    @classmethod
    def _non_empty_permissions(cls, value: str) -> str:
        codes = [part.strip() for part in value.split(",") if part.strip()]
        if not codes:
            raise ValueError("requested_permissions must contain at least one permission code")
        return ",".join(codes)


class JITApprove(BaseModel):
    granted_permissions: str | None = None
    valid_until: datetime | None = None

    @field_validator("granted_permissions", mode="before")
    @classmethod
    def _join_permissions(cls, value: Any) -> Any:
        if isinstance(value, (list, tuple, set)):
            return ",".join(str(item) for item in value)
        return value


class JITReject(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


class JITRevoke(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


# ---------------------------------------------------------------------------
# Incidents (NIS2)
# ---------------------------------------------------------------------------
class IncidentCreate(BaseModel):
    tenant_id: int | None = None
    title: str = Field(min_length=3, max_length=255)
    description: str = Field(min_length=3, max_length=10000)
    severity: IncidentSeverity
    article: IncidentArticle = IncidentArticle.both


class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    severity: IncidentSeverity | None = None
    description: str | None = Field(default=None, min_length=3, max_length=10000)


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
class Message(BaseModel):
    detail: str


class AuditVerifyResult(BaseModel):
    valid: bool
    checked_count: int
    first_mismatch: dict[str, Any] | None = None


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
