# SECURITY_AUDIT.md — BeeInControl Multi-Tenant OT Fleet & NIS2 Access Control Simulator

- Date: 2026-11-22
- Auditor: `security-auditor` subagent
- Scope: `backend/` (`app/`), `frontend/static/js/`, `tests/`
- Method: static analysis of `backend/app/main.py`, `deps.py`, `auth.py`, `audit.py`, `timeutils.py`, `crud.py`, `database.py`, `seed.py`, `models.py`, `schemas.py`, routers (`auth, tenants, users, roles, assets, jit, incidents, audit, system`), frontend core (`app.js`, `auth.js`), `tests/conftest.py`; grep for risky patterns (hardcoded secrets, raw SQL, eval/exec/innerHTML, CORS, `execute()`/`text()`). No runtime re-test; ARCHITECTURE.md claims were verified by inspection.

Severity: Critical / High / Medium / Low / Info.

## 1. Executive summary

Tenant isolation and RBAC enforcement are solid: every router filters by `tenant_id` or calls `enforce_tenant_membership`/`enforce_permission`, and the test suite asserts cross-tenant 403s. JIT time-window enforcement and NIS2 server-side timers are correctly implemented (positive controls below). Two issues are High, several are Medium/Low. Main hot spots: a hardcoded JWT signing secret default, and an unauthenticated seed endpoint that returns demo credentials.

## 2. Findings

### F1 — High — Hardcoded default JWT signing secret
`backend/app/auth.py:19`: `SECRET_KEY = os.getenv("SECRET_KEY", "beeincontrol-dev-secret-change-me")`. `auth.py:17` and `backend/app/database.py:16` load `backend/.env` first; if `.env` is absent or `SECRET_KEY` unset, every JWT for all tenants can be forged by anyone with repo/code access (`auth.py:49-74`). `backend/.env.example:2` gives a weak default string. **Fix:** if no env var, generate a cryptographically random secret at startup, or refuse to start; document a strong example in `.env.example`.

### F2 — High — Unauthenticated seed endpoint leaks demo credentials
`backend/app/routers/system.py:14-16` defines `POST /api/v1/seed` with no auth dependency; it calls `seed_database(db)` which returns `DEMO_CREDENTIALS` including plaintext passwords (`backend/app/seed.py:128-131, 174-186, 260-265`). Anyone can trigger it and read tenant-admin passwords (`NorthGrid123!`, `AquaFlow123!`, etc.). It even returns credentials when already seeded (`seed.py:179-186`). **Fix:** require platform-admin auth (`is_platform_admin` check, as in `routers/tenants.py:53`) and never return passwords in API responses.

### F3 — Medium — No login rate limiting / lockout
`backend/app/routers/auth.py:79-86` only calls `authenticate_user` (bcrypt verify, `backend/app/auth.py:40-46`) — no throttling, no account lockout, no bot challenge. Online password guessing is feasible (seed passwords are long-ish, but brute force of local accounts is still possible). **Fix:** fixed-window rate limit on `/auth/login` per email (+429 on burst), consider progressive delay and 401 logging.

### F4 — Medium — Permissive default CORS
`backend/app/main.py:42-47`: when `CORS_ORIGINS` is unset/empty, `allow_origins=["*"]` and `allow_credentials=False`; `backend/.env.example:5-6` documents `CORS_ORIGINS=*`. With bearer tokens there are no cookies (tokens are read from `sessionStorage`, `frontend/static/js/app.js:134-135`), so `*` mainly lets any website call the API from a user's browser if it holds a token — residual risk. **Fix:** require explicit origins by default in non-dev; keep `*` only for simulator deployments.

### F5 — Medium — Global chain verification exposed to any auditor
`backend/app/routers/audit.py:86-92` (`verify_full_chain`): `enforce_any_permission(db, user, "audit:read")` — any tenant auditor can call the chain-wide `/audit/verify`, learning total link count and mismatch positions across tenants. Low severity (read-only summary). **Fix:** platform-admin-only, or add a tenant-scoped summary endpoint.

### F6 — Medium — Full role/permission catalogue disclosed
`backend/app/routers/roles.py:35-47` (`GET /roles`) and `roles.py:99-107` (`GET /permissions`) return the entire catalogue to any user holding `role:manage`/`user:manage` in any context. A tenant auditor enumerates all roles/permissions platform-wide. **Fix:** scope catalogue responses to the caller's active grants, or add a `role:read`/`permission:read` admin permission.

### F7 — Low — 500 on malformed time bounds
`backend/app/routers/audit.py:23-29` (`_time_bound`) with `backend/app/timeutils.py:27-44` (`parse_iso`): the `except ValueError` falls through to `datetime.strptime(value, ...)` which raises an uncaught `ValueError` for garbage input (e.g., `GET /audit/logs?since=not-a-date`) → HTTP 500 instead of 400. **Fix:** validate in `_time_bound`, return 400 on parse failure.

### F8 — Low — Email enumeration via login timing
`backend/app/auth.py:40-46` (`authenticate_user`): non-existent or inactive users return `None` without bcrypt work; existing users pay a bcrypt cost, creating a timing oracle for account existence. **Fix:** run a dummy bcrypt hash for missing users (constant-time behavior).

### F9 — Low — Demo passwords rendered in DOM
`frontend/static/js/auth.js:26-34`: seeded demo passwords are placed into `data-password` attributes and rendered (`auth.js:27-31`). Intentional for prefill; lower value as secrets but visible to any DOM reader. **Fix:** mask by default (`type="password"` toggle) or show a one-click copy instead.

### F10 — Residual — In-memory logout only
`backend/app/auth.py:24-26, 71-73, 77-81`: revoked `jti`s live in a process-local set; restart clears them. Simulator limitation, acceptable; note for production hardening.

### F11 — Residual — Audit chain integrity depends on DB file integrity
`backend/app/audit.py:63-74, 141-164`: chain verification recomputes SHA-256 hashes from DB rows; SQLite file tamper/restore defeats it, and the `previous.hash if previous else GENESIS_HASH` fallback (`audit.py:74`) re-links a missing predecessor — `verify_chain` still flags the gap. Recommend restrictive file perms / backup integrity checks.

### F12 — Residual — Dangling JIT grants after asset delete
`backend/app/routers/assets.py:180-201`: hard-deletes assets without deactivating grants (`JITAccessGrant.asset_id` FK not enforced by SQLite default). Minor dangling-reference cleanup item.

### F13 — Info — Trivial disclosure
`/api/v1` root lists `docs` (`backend/app/main.py:65-72`); `/docs` and `/openapi.json` are served (only excluded under `/api/...`, `main.py:109`). Acceptable for a local simulator.

## 3. Positive controls

- **Tenant isolation:** every router filters by `tenant_id` or calls `enforce_tenant_membership` (`backend/app/deps.py:165-185`); `is_platform_admin` requires `tenant_id IS NULL` (`deps.py:59-72`). Verified in: `tenants.py:83-94`, `users.py:55-62, 74-92`, `roles.py:125-148`, `assets.py:26-35, 114-122`, `incidents.py:38-40`, `audit.py` router. Cross-tenant 403s asserted by `tests/test_rbac.py`/`tests/test_tenants.py`.
- **RBAC:** `enforce_permission`/`enforce_any_permission` (`deps.py:131-162`) used across routers; UI `can()` is advisory only (`app.js:291-317`).
- **JIT time-bound enforcement (server-side):** window enforced on every grant-reliant action — `grant_is_current` (`backend/app/jit.py:12-17`), `has_active_grant` (`jit.py:34-59`), `active_grant_for_user_asset` (`jit.py:112-139`); `expire_stale_grants` applied lazily on reads (`jit.py:62-101`). `approve_request` caps `valid_until` at `requested_until` and requires future deadline (`routers/jit.py:202-210`); duplicate-active-grant 409 check (`routers/jit.py:212-229`); `use_jit_grant` re-checks membership + permission + active grant (`routers/assets.py:224-241`).
- **NIS2 timers:** deadlines computed server-side at declare (`routers/incidents.py:104-116`, `backend/app/nis2.py:14-19`); timer state derived server-side (`nis2.py:22-75`); PATCH restricted to resolved/closed transitions (`routers/incidents.py:185-239`); overdue flags computed by server.
- **Audit hash chain:** SHA-256, genesis constant, `sequence_no` + `previous_hash` (`backend/app/audit.py:14-44`); `verify_chain` recomputes all entries (`audit.py:105-166`); endpoints `/audit/logs`, `/audit/verify`, `/audit/verify/{id}` (tenant-scoped for non-admins, `routers/audit.py:95-114`); tamper detection covered by `tests/test_audit.py`.
- **Auth/secrets hygiene:** `password_hash` never serialized (`backend/app/crud.py:43-53`); bcrypt hashing/verification (`auth.py:29-35`); JWT HS256 with `exp` + `jti` revocation (`auth.py:49-74`); password length 1–256 on login, 6–256 on create (`schemas.py:23-26, 53-56`); passwords re-hashed on update (`routers/users.py:213-215`).
- **Input validation:** Pydantic v2 schemas on all request bodies (`schemas.py`); ORM everywhere — `text()` used only with static strings (`routers/system.py:25-27`); tenant slugs constrained to `^[a-z0-9-]+$` (`schemas.py:39`).
- **Frontend:** HTML escaper `h()` used in every dynamic `innerHTML` assignment (e.g., `app.js:22-27`); bearer token from `sessionStorage` (`app.js:134-135`), cleared on logout (`app.js:198-203`); 401 → forced re-login (`app.js:151-159`); static path traversal guarded (`main.py:78-88`).
- **API resilience:** `require_permission` factory for tenant-scoped routes (`deps.py:188-211`); `X-Total-Count` paging header (`routers/audit.py:75-82`).

## 4. Recommended fixes (by priority)

1. `backend/app/auth.py:19` — auto-generate a random `SECRET_KEY` when unset/blank; document stronger examples.
2. `backend/app/routers/system.py:14-16` — require platform-admin auth; stop returning `DEMO_CREDENTIALS` in responses (`seed.py:128-131, 260-265`).
3. `backend/app/routers/auth.py:79-86` + `auth.py:40-46` — add login rate limiting and constant-time handling for missing users.
4. `backend/app/main.py:42-47` — default `CORS_ORIGINS` to unset → restrictive; warn on `*`.
5. `backend/app/routers/audit.py:86-92` + `routers/roles.py:35-47, 99-107` — scope global verify/catalogue to platform admins or per-tenant views.
6. `backend/app/routers/audit.py:23-29` + `backend/app/timeutils.py:27-44` — handle parse failure as 400.
7. `backend/app/routers/assets.py:180-201` — deactivate active grants on asset delete.
8. Optional: review `auth.py:71-73` revocation persistence for production; add audit-chain integrity monitoring.

## 5. Noted doc/code drift

- `ARCHITECTURE.md` §9 "JWT with short TTL (e.g., 15 min)" vs `auth.py:21` default of 60 min — minor mismatch; recommend aligning docs or default.
- `ARCHITECTURE.md` §9 says `require_permission(...)` is the standard pattern; codebase actually uses `enforce_permission`/`enforce_any_permission` everywhere (and `require_permission` is unused) — cosmetic.
