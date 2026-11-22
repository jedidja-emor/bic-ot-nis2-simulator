# ARCHITECTURE.md
# BeeInControl Multi-Tenant OT Fleet & NIS2 Access Control Simulator

**Principal Software Architect spec** — concrete, implementation-ready design for backend-dev, frontend-dev, qa-tester, and security-auditor.

---

## 1. System Overview

BeeInControl is a simulator for multi-tenant OT (operational technology) fleet management with NIS2-compliant access control.

- **3 industrial tenants** (energy, water, transport) pre-seeded.
- **Tenant-scoped RBAC**: every data row belongs to a tenant; users/roles/assets/incidents/JIT grants are isolated per tenant.
- **Just-In-Time (JIT) vendor access**: time-bound, approval-gated access to assets for vendor users; auto-expires.
- **NIS2 Article 21 / Article 23 incident timers**: 24h early-warning deadline and 72h authority-notification deadline per incident, with state machine and overdue tracking.
- **Hash-chained audit log**: append-only, tamper-evident chain of all security-relevant events.
- **Stack**: FastAPI + SQLite (single file DB), SQLAlchemy ORM, Pydantic v2 schemas, pytest for backend; vanilla HTML/JS frontend consuming the API.

**Assumptions / non-goals:**
- Single-process simulator; no distributed consensus, no real PLC/OT hardware, no live ICS protocol.
- Authentication = local username/password + JWT (simulated MFA not modeled).
- One SQLite file `beeincontrol.db` at repo root (or `backend/data/beeincontrol.db`).

---

## 2. Data Model — SQLite Schema

All tables use `INTEGER PRIMARY KEY` (autoincrement) IDs. Timestamps are ISO-8601 UTC text (`YYYY-MM-DDTHH:MM:SSZ`). Every tenant-scoped table carries `tenant_id`.

### 2.1 Core tables

**tenants**
| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | INTEGER PK | | |
| name | TEXT | NOT NULL, UNIQUE | e.g. "NorthGrid Energy" |
| slug | TEXT | NOT NULL, UNIQUE | URL-safe, e.g. "northgrid" |
| sector | TEXT | NOT NULL | enum: energy \| water \| transport |
| is_active | BOOLEAN | NOT NULL DEFAULT 1 | |
| created_at | TEXT | NOT NULL | ISO-8601 UTC |

**users**
| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | INTEGER PK | | |
| email | TEXT | NOT NULL, UNIQUE | login identifier |
| full_name | TEXT | NOT NULL | |
| password_hash | TEXT | NOT NULL | bcrypt hash |
| tenant_id | INTEGER | FK tenants.id, NULLABLE | NULL = cross-tenant / platform admin |
| is_vendor | BOOLEAN | NOT NULL DEFAULT 0 | vendor (external) user |
| is_active | BOOLEAN | NOT NULL DEFAULT 1 | |
| created_at | TEXT | NOT NULL | |

**roles**
| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | INTEGER PK | | |
| name | TEXT | NOT NULL, UNIQUE | tenant_admin, site_engineer, viewer, security_officer, vendor_remote |
| scope | TEXT | NOT NULL | enum: tenant \| global |
| is_system | BOOLEAN | NOT NULL DEFAULT 0 | system roles cannot be deleted |

**permissions**
| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | INTEGER PK | | |
| code | TEXT | NOT NULL, UNIQUE | asset:read, asset:write, incident:declare, jit:approve, audit:read, user:manage, tenant:manage |
| resource | TEXT | NOT NULL | e.g. asset, incident, jit, audit, user, tenant |
| action | TEXT | NOT NULL | e.g. read, write, declare, approve, manage |

**role_permissions** (M2M)
| Field | Type | Notes |
|---|---|---|
| role_id | INTEGER PK, FK roles.id | |
| permission_id | INTEGER PK, FK permissions.id | |
| PRIMARY KEY (role_id, permission_id) | | |

**user_roles** (tenant-scoped role assignment)
| Field | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| user_id | INTEGER, FK users.id | |
| role_id | INTEGER, FK roles.id | |
| tenant_id | INTEGER, FK tenants.id | the tenant this grant applies to |
| granted_by | INTEGER, FK users.id | who assigned it |
| granted_at | TEXT | ISO-8601 |
| expires_at | TEXT | NULLABLE; role grant expiry |
| PRIMARY KEY (user_id, role_id, tenant_id) | | one active assignment per user/role/tenant |

### 2.2 OT Fleet

**assets** (fleet devices)
| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | INTEGER PK | | |
| tenant_id | INTEGER | NOT NULL, FK tenants.id | owning tenant |
| asset_tag | TEXT | NOT NULL | unique within tenant, e.g. "PLC-001" |
| name | TEXT | NOT NULL | human-readable |
| type | TEXT | NOT NULL | enum: PLC \| RTU \| HMI \| SENSOR \| CONTROLLER |
| site | TEXT | | physical site name |
| status | TEXT | NOT NULL | enum: online \| offline \| maintenance \| alert |
| last_seen | TEXT | NULLABLE | last heartbeat ISO-8601 |
| created_at | TEXT | NOT NULL | |
| UNIQUE(tenant_id, asset_tag) | | |

### 2.3 JIT Vendor Access

**jit_access_requests**
| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | INTEGER PK | | |
| tenant_id | INTEGER | NOT NULL, FK tenants.id | |
| requesting_user_id | INTEGER | NOT NULL, FK users.id | user who asks (vendor or internal) |
| asset_id | INTEGER | NULLABLE, FK assets.id | NULL = tenant-level access request |
| reason | TEXT | NOT NULL | free text justification |
| requested_permissions | TEXT | NOT NULL | comma-separated permission codes, e.g. "asset:read,asset:write" |
| requested_until | TEXT | NOT NULL | requested end of access ISO-8601 |
| status | TEXT | NOT NULL | enum: pending \| approved \| rejected \| revoked \| expired |
| approved_by | INTEGER | NULLABLE, FK users.id | approver |
| approved_at | TEXT | NULLABLE | |
| created_at | TEXT | NOT NULL | |
| updated_at | TEXT | NOT NULL | |

**jit_access_grants** (active / historical grants)
| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | INTEGER PK | | |
| request_id | INTEGER | NOT NULL, FK jit_access_requests.id | |
| grantee_user_id | INTEGER | NOT NULL, FK users.id | user receiving access (typically vendor) |
| asset_id | INTEGER | NULLABLE, FK assets.id | |
| granted_permissions | TEXT | NOT NULL | comma-separated codes actually granted |
| valid_from | TEXT | NOT NULL | access start ISO-8601 |
| valid_until | TEXT | NOT NULL | hard expiry ISO-8601; access ceases after |
| is_active | BOOLEAN | NOT NULL DEFAULT 1 | set 0 on revoke or expiry |
| revoked_at | TEXT | NULLABLE | |
| revoked_by | INTEGER | NULLABLE, FK users.id | |
| created_at | TEXT | NOT NULL | |

JIT enforcement rule (backend): a grant authorizes action only if `is_active=1` AND `valid_from <= now <= valid_until`. Backend must auto-treat grants past `valid_until` as expired (filter `is_active=1 AND valid_until > now`).

### 2.4 NIS2 Incidents (Art 21 / 23)

**incidents**
| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | INTEGER PK | | |
| tenant_id | INTEGER | NOT NULL, FK tenants.id | |
| title | TEXT | NOT NULL | |
| description | TEXT | NOT NULL | |
| severity | TEXT | NOT NULL | enum: low \| medium \| high \| critical |
| status | TEXT | NOT NULL | enum: open \| early_warning_sent \| notified_authority \| resolved \| closed |
| article | TEXT | NOT NULL | enum: 21 \| 23 \| both |
| declared_at | TEXT | NOT NULL | incident open time (start of both timers) |
| early_warning_deadline | TEXT | NOT NULL | declared_at + 24 h (Art 21) |
| notification_deadline | TEXT | NOT NULL | declared_at + 72 h (Art 23) |
| early_warning_sent_at | TEXT | NULLABLE | when 24h notice sent |
| notification_sent_at | TEXT | NULLABLE | when 72h authority notice sent |
| resolved_at | TEXT | NULLABLE | |
| closed_at | TEXT | NULLABLE | |
| created_at | TEXT | NOT NULL | |
| updated_at | TEXT | NOT NULL | |

**NIS2 timer logic (server-side, enforced on read & on explicit actions):**
- `early_warning_deadline` = `declared_at` + 24 hours.
- `notification_deadline` = `declared_at` + 72 hours.
- Timer state derived per incident:
  - `open` + now < early_warning_deadline → "early_warning_pending", time_remaining = deadline - now.
  - `open` + now >= early_warning_deadline → "early_warning_overdue".
  - `early_warning_sent` + now < notification_deadline → "notification_pending".
  - `early_warning_sent` + now >= notification_deadline → "notification_overdue".
  - `notified_authority` → timers satisfied; awaits resolution.
  - `resolved`/`closed` → timers complete.
- Endpoint `POST /incidents/{id}/early-warning` allowed only when status=`open` (marks `early_warning_sent_at`, status=`early_warning_sent`).
- Endpoint `POST /incidents/{id}/notify` allowed only when status=`early_warning_sent` (marks `notification_sent_at`, status=`notified_authority`).
- A GET `/incidents/timers` returns all incidents with computed `timer_state`, `time_remaining_seconds`, `is_overdue`.

### 2.5 Hash-Chained Audit Log

**audit_log**
| Field | Type | Constraints | Notes |
|---|---|---|---|
| id | INTEGER PK | | |
| tenant_id | INTEGER | NULLABLE, FK tenants.id | NULL = platform/system event |
| actor_user_id | INTEGER | NULLABLE, FK users.id | who performed the action |
| action | TEXT | NOT NULL | e.g. "asset:read", "incident:declare", "jit:grant" |
| target_type | TEXT | NOT NULL | e.g. "asset", "incident", "jit_grant", "user" |
| target_id | TEXT | NOT NULL | stringified id of target |
| details | TEXT | NOT NULL | JSON payload (extra context) |
| event_time | TEXT | NOT NULL | ISO-8601 UTC (monotonic-ish) |
| sequence_no | INTEGER | NOT NULL | global chain sequence (1, 2, 3 …) |
| previous_hash | TEXT | NOT NULL | hash of previous row ("0"*64 for genesis) |
| hash | TEXT | NOT NULL | sha256 of canonical payload |
| created_at | TEXT | NOT NULL | |

**Hash computation** (deterministic, reproducible):
```
payload = f"{sequence_no}|{previous_hash}|{event_time}|{actor_user_id or ''}|{action}|{target_type}|{target_id}|{details}"
hash = sha256(payload.encode('utf-8')).hexdigest()
```
- Insert order = sequence order. `previous_hash` of row N = `hash` of row N-1. Genesis row has `previous_hash = "0"*64`.
- Append-only: no UPDATE/DELETE on `audit_log` rows ever.
- Verification endpoint recomputes every hash in sequence order and reports first mismatch (index, expected vs actual).

---

## 3. RBAC Model

### 3.1 Roles (system + tenant-scoped)

| Role | Scope | Typical permissions |
|---|---|---|
| tenant_admin | tenant | full tenant scope: user:manage, asset:read/write, incident:declare, jit:approve, audit:read (own tenant) |
| site_engineer | tenant | asset:read, asset:write (own assets), incident:read |
| viewer | tenant | asset:read, incident:read, audit:read (own tenant) |
| security_officer | tenant | incident:read/write, audit:read, jit:read |
| vendor_remote | tenant | asset:read (only via active JIT grant), time-bound |
| platform_admin | global | tenant:manage, user:manage (cross-tenant), audit:read (all) |

### 3.2 Permission codes (concrete)

- `asset:read` — view fleet assets
- `asset:write` — create/update/delete assets
- `asset:jit_access` — use an active JIT grant on an asset (simulated OT action)
- `incident:read` — view incidents
- `incident:declare` — create an incident
- `incident:early_warning` — send Art 21 notice
- `incident:notify` — send Art 23 notice
- `jit:request` — create JIT access request
- `jit:approve` — approve/reject/revoke JIT requests
- `jit:read` — view JIT requests/grants
- `user:manage` — create/update users and role assignments
- `role:manage` — create/update roles
- `tenant:manage` — create/update tenants (platform only)
- `audit:read` — view audit log + verify chain

### 3.3 Tenant scoping rule (enforced in every dependency)

1. Resolve JWT → `current_user`.
2. Determine `tenant_id` context:
   - For tenant-scoped endpoints, `tenant_id` comes from path/query/body OR from the target resource's owning tenant.
   - `current_user` must have a `user_roles` row for that `tenant_id`, OR be a `platform_admin` (global scope) with `tenant_id IS NULL`.
3. Permission check: `current_user` holds (via user_roles → role → role_permissions) the required permission code for that tenant context.
4. Row-level filter: every SELECT on tenant-scoped tables adds `WHERE tenant_id = :tenant_context` (unless platform_admin requesting all).
5. Cross-tenant access is denied by default (403).

### 3.4 RBAC / NIS2 policy matrix

| Action | Required permission | Tenant context | NIS2 relevance |
|---|---|---|---|
| List/create assets | asset:read / asset:write | owner tenant | — |
| Declare incident | incident:declare | owner tenant | starts Art 21/23 timers |
| Send early warning | incident:early_warning | owner tenant | Art 21, ≤24h |
| Notify authority | incident:notify | owner tenant | Art 23, ≤72h |
| Create JIT request | jit:request | owner tenant | vendor access |
| Approve JIT | jit:approve | owner tenant | gates vendor access |
| Use JIT grant | asset:jit_access | owner tenant + active grant | time-bound OT access |
| Read audit (own tenant) | audit:read | owner tenant | — |
| Read audit (all) | audit:read | global | platform_admin only |
| Verify chain | audit:read | owner tenant / global | tamper evidence |

---

## 4. JIT Vendor Access Flow

States (on `jit_access_requests.status`): `pending → approved | rejected`; approved grant lifecycle: `active → revoked | expired`.

Flow:
1. Vendor user (or internal requester) `POST /jit/requests` with `tenant_id`, optional `asset_id`, `reason`, `requested_permissions`, `requested_until`. Creates request with `status=pending`. Audit event `jit:request`.
2. Approver (has `jit:approve`) `POST /jit/requests/{id}/approve` → sets `status=approved`, `approved_by`, `approved_at`, creates `jit_access_grants` row (`is_active=1`, `valid_from=now`, `valid_until=requested_until` or earlier cap), `granted_permissions` = intersection of requested and allowed. Audit event `jit:grant`.
3. Or `POST /jit/requests/{id}/reject` → `status=rejected`. Audit event `jit:reject`.
4. Active grant enables simulated OT action only while `is_active=1 AND now between valid_from and valid_until`. Backend enforces on every asset-action that requires `asset:jit_access`.
5. Approver `POST /jit/grants/{id}/revoke` → grant `is_active=0`, `revoked_at`, `revoked_by`; request `status=revoked`. Audit event `jit:revoke`.
6. At `valid_until` the grant is treated as expired (`is_active` effectively 0); a nightly/on-read sweep may set `request.status=expired` and grant `is_active=0`. Audit event `jit:expire`.

Rule: a vendor user cannot hold more than one active grant per asset at a time (enforced at approve time → 409).

---

## 5. NIS2 Incident Timer Logic (Art 21 / 23)

Article 21 = incident management / early warning (≤24 h). Article 23 = reporting to competent authority (≤72 h).

State machine (`incidents.status`):
`open → early_warning_sent → notified_authority → resolved → closed`

Deadlines computed at declare time:
- `early_warning_deadline = declared_at + 24h`
- `notification_deadline = declared_at + 72h`

Derived timer state (read-only, computed in endpoint layer):
- `open` & `now < early_warning_deadline` → `early_warning_pending`, `time_remaining = early_warning_deadline - now`
- `open` & `now >= early_warning_deadline` → `early_warning_overdue`
- `early_warning_sent` & `now < notification_deadline` → `notification_pending`
- `early_warning_sent` & `now >= notification_deadline` → `notification_overdue`
- `notified_authority` → `notified` (timers met)
- `resolved` / `closed` → `complete`

Endpoints:
- `POST /incidents` (declare) → `status=open`, computes both deadlines, audit `incident:declare`.
- `POST /incidents/{id}/early-warning` → requires `status=open` + `incident:early_warning` perm → sets `early_warning_sent_at=now`, `status=early_warning_sent`. If called after `early_warning_deadline`, still allowed but `is_overdue=true` flag returned.
- `POST /incidents/{id}/notify` → requires `status=early_warning_sent` + `incident:notify` perm → sets `notification_sent_at=now`, `status=notified_authority`. Overdue flag if past `notification_deadline`.
- `GET /incidents/timers` → list all incidents annotated with `timer_state`, `time_remaining_seconds`, `is_overdue`, `early_warning_deadline`, `notification_deadline`.

Resolution (`PATCH /incidents/{id}` status → `resolved` then `closed`) sets `resolved_at`/`closed_at`.

---

## 6. Hash-Chained Audit Log Design

- Every security-relevant state change (login, role assign, asset CRUD, JIT request/approve/revoke, incident declare/notify/resolve, tenant/user create) writes an `audit_log` row.
- `sequence_no` assigned at insert as `MAX(sequence_no)+1` within a transaction (single-writer SQLite; fine for simulator).
- `hash = sha256(sequence_no || previous_hash || event_time || actor_user_id || action || target_type || target_id || details)`.
- `previous_hash` = prior row's `hash`; genesis = `"0"*64`.
- Append-only enforced: no UPDATE/DELETE on `audit_log` in application code; SQLite file permissions restrict direct writes.
- `GET /audit/verify` walks rows ordered by `sequence_no`, recomputes hashes, returns `valid: true/false`, `first_mismatch` detail if invalid.
- `GET /audit/logs` supports pagination (`limit`, `offset`), `tenant_id` filter, `action` filter, `actor_user_id` filter, `since`/`until` time range.

---

## 7. API Surface (FastAPI)

Base path: `/api/v1`. Auth: Bearer JWT in `Authorization` header. Errors: JSON `{detail: str}` with standard HTTP statuses.

### 7.1 Auth
| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/v1/auth/login` | email + password → `{access_token, token_type, user}` | none |
| POST | `/api/v1/auth/logout` | revoke token (simulated) | bearer |
| GET | `/api/v1/auth/me` | current user + roles + tenant context | bearer |

### 7.2 Tenants
| Method | Path | Description | Perm |
|---|---|---|---|
| GET | `/api/v1/tenants` | list (platform_admin: all; else own) | tenant:manage |
| POST | `/api/v1/tenants` | create tenant | tenant:manage (global) |
| GET | `/api/v1/tenants/{id}` | get tenant | tenant:manage or member |
| PATCH | `/api/v1/tenants/{id}` | update is_active/sector/name | tenant:manage |

Request body (create/update): `{name, slug, sector, is_active}`.

### 7.3 Users
| Method | Path | Description | Perm |
|---|---|---|---|
| GET | `/api/v1/users` | list, filter `tenant_id` | user:manage |
| POST | `/api/v1/users` | create user (+ optional initial role assign) | user:manage |
| GET | `/api/v1/users/{id}` | get user | user:manage |
| PATCH | `/api/v1/users/{id}` | update (active, vendor flag, password) | user:manage |
| DELETE | `/api/v1/users/{id}` | soft-delete (is_active=0) | user:manage |

Tenant scoping: non-platform users may only see/manage users in their own tenant(s).

### 7.4 Roles & Permissions
| Method | Path | Description | Perm |
|---|---|---|---|
| GET | `/api/v1/roles` | list roles (system + tenant-scoped) | role:manage |
| POST | `/api/v1/roles` | create role | role:manage |
| GET | `/api/v1/permissions` | list all permission codes | role:manage |
| POST | `/api/v1/user-roles` | assign role to user in tenant `{user_id, role_id, tenant_id, expires_at}` | user:manage |
| DELETE | `/api/v1/user-roles/{id}` | remove assignment | user:manage |

### 7.5 Assets (OT Fleet)
| Method | Path | Description | Perm |
|---|---|---|---|
| GET | `/api/v1/assets` | list, filter `tenant_id`, `status`, `type` | asset:read |
| POST | `/api/v1/assets` | create asset `{tenant_id, asset_tag, name, type, site, status}` | asset:write |
| GET | `/api/v1/assets/{id}` | get asset | asset:read |
| PATCH | `/api/v1/assets/{id}` | update asset | asset:write |
| DELETE | `/api/v1/assets/{id}` | delete asset | asset:write |
| GET | `/api/v1/assets/{id}/jit-active` | active JIT grants on this asset | jit:read |

Row filter: `WHERE tenant_id = context`.

### 7.6 JIT Access
| Method | Path | Description | Perm |
|---|---|---|---|
| GET | `/api/v1/jit/requests` | list requests, filter `tenant_id`, `status`, `asset_id` | jit:read |
| POST | `/api/v1/jit/requests` | create request `{tenant_id, asset_id?, reason, requested_permissions, requested_until}` | jit:request |
| GET | `/api/v1/jit/requests/{id}` | get request | jit:read |
| POST | `/api/v1/jit/requests/{id}/approve` | approve → create grant `{granted_permissions?, valid_until?}` | jit:approve |
| POST | `/api/v1/jit/requests/{id}/reject` | reject | jit:approve |
| GET | `/api/v1/jit/grants` | list grants, filter `tenant_id`, `is_active`, `asset_id` | jit:read |
| GET | `/api/v1/jit/grants/{id}` | get grant | jit:read |
| POST | `/api/v1/jit/grants/{id}/revoke` | revoke grant | jit:approve |

### 7.7 Incidents (NIS2)
| Method | Path | Description | Perm |
|---|---|---|---|
| GET | `/api/v1/incidents` | list, filter `tenant_id`, `status`, `severity` | incident:read |
| POST | `/api/v1/incidents` | declare `{title, description, severity, article}` | incident:declare |
| GET | `/api/v1/incidents/{id}` | get incident | incident:read |
| PATCH | `/api/v1/incidents/{id}` | update (status→resolved/closed, severity, description) | incident:declare |
| POST | `/api/v1/incidents/{id}/early-warning` | send Art 21 notice | incident:early_warning |
| POST | `/api/v1/incidents/{id}/notify` | send Art 23 authority notice | incident:notify |
| GET | `/api/v1/incidents/timers` | all incidents + computed timer states | incident:read |

### 7.8 Audit
| Method | Path | Description | Perm |
|---|---|---|---|
| GET | `/api/v1/audit/logs` | list entries, pagination + filters | audit:read |
| GET | `/api/v1/audit/verify` | verify full chain integrity | audit:read |
| GET | `/api/v1/audit/verify/{entry_id}` | verify prefix up to entry | audit:read |

### 7.9 Seed / System
| Method | Path | Description | Auth |
|---|---|---|---|
| POST | `/api/v1/seed` | (re)seed 3 tenants + demo users/roles/assets (dev only) | none or admin |
| GET | `/api/v1/health` | health + DB version | none |

---

## 8. Frontend — Pages, Components, Interactions

Vanilla HTML/CSS/JS (no build step required), single-page app style with fetch to `/api/v1`. JWT stored in `sessionStorage` (or `localStorage` with note). All API calls include `Authorization: Bearer <token>`.

### 8.1 Pages
1. **Login** (`/login`) — email/password form, POST `/auth/login`, redirect to dashboard.
2. **Dashboard** (`/`) — tenant selector, KPI cards (assets by status, active JIT grants, open incidents, overdue NIS2 timers), recent audit entries.
3. **Tenants** (`/tenants`) — list/create/edit tenants (platform admin only).
4. **Users & Roles** (`/users`) — user table, create/edit user, assign roles per tenant.
5. **Assets / Fleet** (`/assets`) — asset table, create/edit, status badge, link to JIT grants.
6. **JIT Access** (`/jit`) — two panels: (a) requests to approve (approver view: approve/reject buttons), (b) my active grants (vendor view: revoke, expiry countdown).
7. **Incidents (NIS2)** (`/incidents`) — incident table, declare form, timer widgets with `early_warning_deadline` / `notification_deadline`, buttons "Send Early Warning" / "Notify Authority" (disabled by state/perm), overdue highlighting (red).
8. **Audit Log** (`/audit`) — paginated log table, filters (tenant, action, actor, date range), "Verify Chain" button calling `/audit/verify` showing valid/invalid banner.

### 8.2 Shared components
- `ApiClient` — fetch wrapper with auth header, auto 401 → redirect to login.
- `TenantContext` — current tenant id selector (stored in sessionStorage).
- `PermissionGuard` — hides/shows UI elements based on user permissions from `/auth/me`.
- `TimerWidget` — counts down `time_remaining_seconds`, shows overdue state.
- `HashChainBadge` — shows audit verify status.

### 8.3 Key interactions
- Declaring an incident auto-starts both timers; timer widget recomputes every 60s (client) but deadlines are authoritative from API `/incidents/timers`.
- Approving a JIT request creates a grant; vendor sees it in "My Grants" with expiry countdown; after `valid_until` the UI marks it expired (API returns `is_active=0` / expired).
- Verify chain: click → GET `/audit/verify` → green "Chain valid" or red "Tamper detected at entry N".

---

## 9. Security Considerations

- **Tenant isolation**: every data access filtered by `tenant_id`; platform_admin is the only cross-tenant reader. Unit tests must assert 403 for cross-tenant access.
- **Authentication**: bcrypt password hashes, JWT with short TTL (e.g. 15 min) + refresh concept noted (simulator: single access token).
- **Authorization**: permission checked in FastAPI dependency (`Depends(require_permission("code"))`), never only in UI.
- **JIT time-bound enforcement**: backend checks `valid_from <= now <= valid_until` on every grant-relying action; client-side expiry is UI only.
- **Audit immutability**: `audit_log` append-only; hash chain makes tampering detectable; `/audit/verify` endpoint.
- **NIS2 timers server-side**: deadlines computed server-side at declare; client countdown is advisory.
- **Input validation**: Pydantic v2 schemas on all request bodies; SQLAlchemy ORM prevents SQL injection.
- **CORS**: restrict to frontend origin in production; simulator may allow `*` with note.
- **Secrets**: `SECRET_KEY` via env var (`.env.example`), never committed.
- **No plaintext passwords**: never return password_hash in responses.

---

## 10. Test Strategy (pytest)

Framework: `pytest` + `fastapi.TestClient` (Starlette) + `sqlite3` in-memory or temp file DB per test.

### 10.1 Fixtures (`tests/conftest.py`)
- `db` / `session` — fresh SQLite DB per test (create_all + drop_all).
- `client` — TestClient bound to app with override `get_db`.
- `seed_tenants` — insert the 3 default tenants.
- `seed_users` — platform_admin + one user per tenant + one vendor.
- `auth_headers(user)` — helper returning Bearer token (or mock dependency bypass).
- `make_token(user)` — JWT sign helper matching backend.

### 10.2 Test modules
| File | Coverage |
|---|---|
| `test_auth.py` | login success/failure, token invalid, /auth/me |
| `test_tenants.py` | CRUD, platform_admin vs tenant user isolation |
| `test_rbac.py` | permission matrix, tenant-scoping, 403 cross-tenant, role assign/remove |
| `test_assets.py` | CRUD, tenant filter, status enum |
| `test_jit.py` | request → approve → grant → use-window → revoke → expire; double-active-grant 409 |
| `test_incidents.py` | declare computes deadlines, early-warning/notify transitions, overdue states, timer endpoint |
| `test_audit.py` | chain append-only, verify valid, tamper detection (mutate hash → invalid) |
| `test_seed.py` | seed creates exactly 3 tenants and expected users |

### 10.3 Conventions
- Tests use `pytest.mark.unit` / `pytest.mark.integration` markers.
- Assert HTTP status + JSON body shape + DB state (via session query).
- NIS2 timer tests use `freezegun` or monkeypatched `datetime.utcnow` to simulate crossing 24h/72h deadlines.
- Target: ≥ 40 tests, all passing, coverage of auth/RBAC/JIT/NIS2/audit.

---

## 11. File / Directory Structure

```
E:\my-dev-office\                          (repo root)
├── ARCHITECTURE.md                        (this file)
├── WORKFLOW_STATE.json                    (agent handoff state)
├── AGENTS.md                              (team protocol - do not edit)
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                        # FastAPI app, routers, middleware
│   │   ├── database.py                    # SQLAlchemy engine, session, Base
│   │   ├── models.py                      # ORM models (all tables §2)
│   │   ├── schemas.py                     # Pydantic v2 request/response schemas
│   │   ├── crud.py                        # DB query helpers
│   │   ├── auth.py                        # password hashing, JWT, login
│   │   ├── deps.py                        # get_db, get_current_user, require_permission
│   │   ├── audit.py                       # hash chain insert + verify
│   │   ├── nis2.py                        # deadline/timer computation
│   │   ├── jit.py                         # JIT lifecycle helpers
│   │   ├── seed.py                        # seed data (3 tenants)
│   │   └── routers/
│   │       ├── __init__.py
│   │       ├── auth.py
│   │       ├── tenants.py
│   │       ├── users.py
│   │       ├── roles.py
│   │       ├── assets.py
│   │       ├── jit.py
│   │       ├── incidents.py
│   │       └── audit.py
│   ├── requirements.txt                   # fastapi, sqlalchemy, pydantic, bcrypt, pyjwt, python-dotenv, pytest, httpx
│   ├── .env.example                       # SECRET_KEY, DATABASE_URL, ACCESS_TOKEN_EXPIRE_MINUTES
│   └── run.py                             # uvicorn entrypoint
├── frontend/
│   ├── index.html                         # SPA shell + nav
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css
│   │   └── js/
│   │       ├── app.js                     # router + ApiClient + TenantContext
│   │       ├── auth.js
│   │       ├── tenants.js
│   │       ├── users.js
│   │       ├── assets.js
│   │       ├── jit.js
│   │       ├── incidents.js
│   │       └── audit.js
│   └── pages/                             # optional per-page HTML (login, dashboard, ...)
│       ├── login.html
│       ├── dashboard.html
│       ├── tenants.html
│       ├── users.html
│       ├── assets.html
│       ├── jit.html
│       ├── incidents.html
│       └── audit.html
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_auth.py
│   ├── test_tenants.py
│   ├── test_rbac.py
│   ├── test_assets.py
│   ├── test_jit.py
│   ├── test_incidents.py
│   └── test_audit.py
├── pytest.ini                             # or pyproject.toml [tool.pytest]
└── .env.example
```

---

## 12. Implementation Notes for Downstream Agents

- **backend-dev**: implement models first (§2), then auth/deps, then routers in order: auth → tenants → users → roles → assets → jit → incidents → audit. Enforce `tenant_id` filtering in every router. Do not write application source code? No — backend-dev writes backend code. This doc is the contract.
- **frontend-dev**: consume `/api/v1` per §7; use `sessionStorage` for JWT; implement the 8 pages §8.1; no build step required.
- **qa-tester**: pytest suite per §10 against `TestClient` + temp SQLite.
- **security-auditor**: verify tenant isolation, JWT handling, append-only audit, no plaintext passwords, CORS/secret handling; output `SECURITY_AUDIT.md`.

End of specification.
