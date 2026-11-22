"""Password hashing, JWT issuing/validation and token revocation."""
from __future__ import annotations

import logging
import os
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
import jwt
from dotenv import load_dotenv
from sqlalchemy.orm import Session

from .models import User

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

logger = logging.getLogger(__name__)


def _resolve_secret_key() -> str:
    """Return the configured JWT signing key, or a secure ephemeral fallback.

    A configured ``SECRET_KEY`` (environment or backend/.env) is required for
    stable tokens across restarts.  When it is unset or blank we generate a
    cryptographically random key instead of falling back to a known default.
    """
    configured = (os.getenv("SECRET_KEY") or "").strip()
    if configured:
        return configured
    logger.warning(
        "SECRET_KEY is not set; generated an ephemeral random JWT signing key. "
        "Set SECRET_KEY in backend/.env for stable tokens across restarts."
    )
    return secrets.token_urlsafe(64)


SECRET_KEY = _resolve_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "10"))

# Simulated logout: revoked token IDs are kept in-process for the simulator.
_revoked_jtis: set[str] = set()
_revoked_lock = threading.Lock()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def authenticate_user(db: Session, email: str, password: str) -> User | None:
    user = db.query(User).filter(User.email == email.lower().strip()).first()
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def create_access_token(user: User, expires_minutes: int | None = None) -> tuple[str, dict]:
    now = datetime.now(timezone.utc)
    minutes = ACCESS_TOKEN_EXPIRE_MINUTES if expires_minutes is None else expires_minutes
    jti = uuid.uuid4().hex
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "tenant_id": user.tenant_id,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=minutes)).timestamp()),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, payload


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT. Raises ``jwt.PyJWTError`` on failure."""
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    jti = payload.get("jti")
    if not jti:
        raise jwt.InvalidTokenError("missing token id")
    with _revoked_lock:
        if jti in _revoked_jtis:
            raise jwt.InvalidTokenError("token revoked")
    return payload


def revoke_token(payload: dict) -> None:
    jti = payload.get("jti")
    if jti:
        with _revoked_lock:
            _revoked_jtis.add(jti)


def reset_revoked_tokens() -> None:
    """Test helper."""
    with _revoked_lock:
        _revoked_jtis.clear()
