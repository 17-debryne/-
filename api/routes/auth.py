from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from mcp_agent_safe_protecter.api.app_database import login_throttle_key
from mcp_agent_safe_protecter.api.deps import AuthPrincipal, require_auth
from mcp_agent_safe_protecter.api.jwt_util import issue_access_token
from mcp_agent_safe_protecter.api.security_audit import audit_security

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginBody(BaseModel):
    login: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="用户名、邮箱或手机号",
    )
    password: str = Field(..., min_length=1, max_length=1024)


@router.post("/login")
def login(request: Request, body: LoginBody) -> dict[str, str | int]:
    app_db = getattr(request.app.state, "app_db", None)
    lk = login_throttle_key(body.login)
    if app_db is not None and app_db.is_login_locked(lk):
        audit_security(
            request,
            "auth_login_locked",
            login_key_prefix=lk[:16],
        )
        raise HTTPException(
            status_code=429,
            detail="登录尝试过多，请稍后再试",
        )

    subject: str | None = None
    istore = getattr(request.app.state, "identity_store", None)
    if istore is not None:
        subject = istore.verify_password_login(body.login, body.password)
    legacy = request.app.state.user_store
    if subject is None and legacy.verify(body.login, body.password):
        subject = body.login

    if subject is None:
        if app_db is not None:
            app_db.record_login_failure(lk)
        audit_security(request, "auth_login_failure", login_key_prefix=lk[:16])
        raise HTTPException(status_code=401, detail="账号或密码错误")

    if app_db is not None:
        app_db.record_login_success(lk)
    audit_security(request, "auth_login_success", subject=subject)

    secret = request.app.state.jwt_secret
    ttl = int(os.environ.get("MASP_JWT_TTL_SEC", "86400"))
    token = issue_access_token(secret, subject, ttl_sec=ttl)
    return {"access_token": token, "token_type": "bearer", "expires_in": ttl}


@router.get("/me")
def me(auth: AuthPrincipal = Depends(require_auth)) -> dict[str, str]:
    return {"subject": auth.subject, "kind": auth.kind}
