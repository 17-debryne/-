from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from mcp_agent_safe_protecter.api.admin_hmac import verify_admin_hmac
from mcp_agent_safe_protecter.api.jwt_util import decode_access_token


@dataclass(frozen=True, slots=True)
class AuthPrincipal:
    """已通过认证的调用方标识。"""

    subject: str
    kind: str  # jwt | api_key | admin_hmac


_bearer = HTTPBearer(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def _try_jwt_or_api_key(
    request: Request,
    creds: HTTPAuthorizationCredentials | None,
    api_key: str | None,
) -> AuthPrincipal | None:
    expected_key = os.environ.get("MASP_API_KEY", "dev-change-me-in-production")

    if api_key and expected_key:
        try:
            if secrets.compare_digest(api_key, expected_key):
                return AuthPrincipal(subject="api_key", kind="api_key")
        except (TypeError, ValueError):
            pass

    if creds and creds.scheme.lower() == "bearer" and creds.credentials:
        secret = getattr(request.app.state, "jwt_secret", None)
        if not secret:
            raise HTTPException(status_code=500, detail="JWT 未初始化")
        try:
            payload = decode_access_token(secret, creds.credentials)
            sub = str(payload.get("sub", "")).strip()
            if not sub:
                raise HTTPException(status_code=401, detail="令牌缺少主体")
            jti = payload.get("jti")
            if jti:
                istore = getattr(request.app.state, "identity_store", None)
                if istore is not None and istore.is_token_revoked(str(jti)):
                    raise HTTPException(
                        status_code=401,
                        detail="令牌已注销",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
            return AuthPrincipal(subject=sub, kind="jwt")
        except jwt.PyJWTError as e:
            raise HTTPException(
                status_code=401,
                detail="无效或已过期的令牌",
                headers={"WWW-Authenticate": "Bearer"},
            ) from e

    return None


async def require_auth(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    api_key: str | None = Security(_api_key_header),
) -> AuthPrincipal:
    p = await _try_jwt_or_api_key(request, creds, api_key)
    if p is not None:
        return p

    raise HTTPException(
        status_code=401,
        detail="需要 Authorization: Bearer <JWT>（先登录）或有效 X-API-Key",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_admin_access(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    api_key: str | None = Security(_api_key_header),
) -> AuthPrincipal:
    """
    管理接口：若配置 ``MASP_ADMIN_HMAC_SECRET``，则 **HMAC 与 JWT/API Key 二选一**；
    未配置 HMAC 密钥时，等价于 ``require_auth``。
    """
    hmac_secret = os.environ.get("MASP_ADMIN_HMAC_SECRET", "").strip()
    if hmac_secret and verify_admin_hmac(request, hmac_secret):
        return AuthPrincipal(subject="admin_hmac", kind="admin_hmac")

    p = await _try_jwt_or_api_key(request, creds, api_key)
    if p is not None:
        return p

    if hmac_secret:
        detail = (
            "管理接口需要有效 HMAC（X-Masp-Timestamp / X-Masp-Signature），"
            "或 Authorization: Bearer JWT / X-API-Key"
        )
    else:
        detail = "需要 Authorization: Bearer <JWT> 或有效 X-API-Key"
    raise HTTPException(
        status_code=401,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_api_key(key: str | None = Security(_api_key_header)) -> str:
    """仅 API Key（兼容旧集成）；新界面请优先使用 ``require_auth``。"""
    expected = os.environ.get("MASP_API_KEY", "dev-change-me-in-production")
    if not key or key != expected:
        raise HTTPException(status_code=401, detail="无效或未提供 X-API-Key")
    return key
