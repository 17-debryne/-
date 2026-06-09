from __future__ import annotations

import os
import time
import uuid
from pathlib import Path

import jwt


def resolve_jwt_secret(data_dir: Path) -> str:
    env = os.environ.get("MASP_JWT_SECRET", "").strip()
    if env:
        return env
    auth = Path(data_dir) / "auth"
    auth.mkdir(parents=True, exist_ok=True)
    p = auth / ".jwt_secret"
    if p.exists():
        return p.read_text(encoding="utf-8").strip()
    import secrets as sec

    secret = sec.token_hex(32)
    p.write_text(secret, encoding="utf-8")
    return secret


def issue_access_token(secret: str, subject: str, *, ttl_sec: int | None = None) -> str:
    ttl = ttl_sec
    if ttl is None:
        ttl = int(os.environ.get("MASP_JWT_TTL_SEC", "86400"))
    now = int(time.time())
    jti = str(uuid.uuid4())
    payload = {"sub": subject, "iat": now, "exp": now + ttl, "jti": jti}
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_access_token(secret: str, token: str) -> dict:
    return jwt.decode(token, secret, algorithms=["HS256"])
