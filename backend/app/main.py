"""FastAPI application entrypoint for BeeInControl."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .database import REPO_ROOT, SessionLocal, init_db
from .routers import assets, audit, auth, incidents, jit, roles, system, tenants, users
from .seed import seed_database

FRONTEND_DIR = REPO_ROOT / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Pre-seed the simulator on first boot; idempotent on later boots.
    try:
        with SessionLocal() as db:
            seed_database(db)
    except Exception as exc:  # pragma: no cover - startup should not crash the API
        print(f"[startup] seed skipped: {exc}")
    yield


app = FastAPI(
    title="BeeInControl API",
    description=(
        "Multi-tenant OT fleet & NIS2 access control simulator "
        "(RBAC, JIT vendor access, NIS2 Art. 21/23 timers, hash-chained audit)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

_cors_env = os.getenv("CORS_ORIGINS", "*").strip()
_cors_origins = ["*"] if _cors_env in ("", "*") else [item.strip() for item in _cors_env.split(",") if item.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_origins != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count"],
)

API_PREFIX = "/api/v1"
app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(tenants.router, prefix=API_PREFIX)
app.include_router(users.router, prefix=API_PREFIX)
app.include_router(roles.router, prefix=API_PREFIX)
app.include_router(assets.router, prefix=API_PREFIX)
app.include_router(jit.router, prefix=API_PREFIX)
app.include_router(incidents.router, prefix=API_PREFIX)
app.include_router(audit.router, prefix=API_PREFIX)
app.include_router(system.router, prefix=API_PREFIX)


@app.get("/api/v1", include_in_schema=False)
def api_root():
    return {
        "name": "BeeInControl API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": f"{API_PREFIX}/health",
    }


# ---------------------------------------------------------------------------
# Static frontend serving (vanilla SPA in ../frontend)
# ---------------------------------------------------------------------------
def _safe_frontend_file(relative_path: str) -> Path | None:
    if not FRONTEND_DIR.exists():
        return None
    candidate = (FRONTEND_DIR / relative_path).resolve()
    try:
        candidate.relative_to(FRONTEND_DIR.resolve())
    except ValueError:
        return None
    if candidate.is_file():
        return candidate
    return None


if (FRONTEND_DIR / "static").exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR / "static"), name="static")


@app.get("/", include_in_schema=False)
def serve_index():
    index = _safe_frontend_file("index.html")
    if index is None:
        return {
            "name": "BeeInControl API",
            "message": "Frontend not built yet. API is available under /api/v1.",
            "docs": "/docs",
        }
    return FileResponse(index)


@app.get("/{full_path:path}", include_in_schema=False)
def serve_frontend(full_path: str):
    if full_path.startswith("api/") or full_path in {"docs", "redoc", "openapi.json"}:
        raise HTTPException(status_code=404, detail="Not found")

    direct = _safe_frontend_file(full_path)
    if direct is not None:
        return FileResponse(direct)

    # /login -> /pages/login.html when per-page HTML exists.
    page = _safe_frontend_file(f"pages/{full_path}.html")
    if page is not None:
        return FileResponse(page)

    index = _safe_frontend_file("index.html")
    if index is not None:
        return FileResponse(index)
    raise HTTPException(status_code=404, detail="Not found")
