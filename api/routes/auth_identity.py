from __future__ import annotations

import logging
import os
import re
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from mcp_agent_safe_protecter.api.app_database import login_throttle_key
from mcp_agent_safe_protecter.api.jwt_util import decode_access_token, issue_access_token
from mcp_agent_safe_protecter.api.security_audit import audit_security
from mcp_agent_safe_protecter.identity.email_sender import send_otp_email, send_verification_link_email
from mcp_agent_safe_protecter.identity.oauth_providers import (
    qq_authorize_url,
    qq_exchange_code,
    qq_openid,
    qq_user_info,
    wechat_exchange_code,
    wechat_userinfo,
    wechat_web_authorize_url,
)
from mcp_agent_safe_protecter.identity.sms_sender import send_otp_sms
from mcp_agent_safe_protecter.identity.store import IdentityStore, is_valid_email, normalize_phone

router = APIRouter(prefix="/api/v1/auth", tags=["identity"])

_LOG = logging.getLogger(__name__)

_bearer_required = HTTPBearer(auto_error=True)

REGISTER_EMAIL_LINK_PURPOSE = "register_email_link"


def _public_base(request: Request) -> str:
    base = os.environ.get("MASP_PUBLIC_BASE_URL", "").strip().rstrip("/")
    if base:
        return base
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("host") or request.headers.get("x-forwarded-host")
    if not host:
        raise HTTPException(
            status_code=503,
            detail="请配置 MASP_PUBLIC_BASE_URL，或通过 Host / X-Forwarded-* 提供公网地址",
        )
    return f"{proto}://{host}"


def _otp_ttl() -> int:
    return int(os.environ.get("MASP_OTP_TTL_SEC", "600"))


def _suggest_username_from_email(email: str) -> str:
    local = email.split("@", 1)[0]
    base = re.sub(r"[^a-zA-Z0-9_\u4e00-\u9fff]", "_", local)
    if len(base) < 2:
        base = "user"
    return base[:24]


class EmailSendBody(BaseModel):
    email: str = Field(..., min_length=3, max_length=128)


class EmailCompleteBody(BaseModel):
    email: str = Field(..., min_length=3, max_length=128)
    code: str = Field(..., min_length=4, max_length=16)
    password: str = Field(..., min_length=6, max_length=256)
    username: str | None = Field(None, max_length=32)


class EmailLinkCompleteBody(BaseModel):
    email: str = Field(..., min_length=3, max_length=128)
    token: str = Field(..., min_length=10, max_length=512)
    password: str = Field(..., min_length=6, max_length=256)
    username: str | None = Field(None, max_length=32)


class PhoneSendBody(BaseModel):
    phone: str = Field(..., min_length=11, max_length=20)


class PhoneCompleteBody(BaseModel):
    phone: str = Field(..., min_length=11, max_length=20)
    code: str = Field(..., min_length=4, max_length=16)
    password: str = Field(..., min_length=6, max_length=256)
    username: str | None = Field(None, max_length=32)


@router.post("/register/email/send")
def register_email_send(request: Request, body: EmailSendBody) -> dict[str, str]:
    if not is_valid_email(body.email):
        raise HTTPException(status_code=400, detail="邮箱格式不正确")
    store: IdentityStore = request.app.state.identity_store
    addr = body.email.strip().lower()
    code = f"{secrets.randbelow(900000) + 100000:06d}"
    store.save_verification("email", addr, code, "register_email", _otp_ttl())
    send_otp_email(addr, code, purpose="邮箱注册")
    audit_security(
        request,
        "auth_register_email_otp_requested",
        identity_prefix=login_throttle_key(addr)[:16],
    )
    return {"detail": "验证码已发送（若未配置 SMTP 请查看日志或 MASP_OTP_LOG_PLAINTEXT）"}


@router.post("/register/email/complete")
def register_email_complete(request: Request, body: EmailCompleteBody) -> dict[str, str]:
    if not is_valid_email(body.email):
        raise HTTPException(status_code=400, detail="邮箱格式不正确")
    store: IdentityStore = request.app.state.identity_store
    addr = body.email.strip().lower()
    if not store.consume_verification("email", addr, body.code, "register_email"):
        raise HTTPException(status_code=400, detail="验证码无效或已过期")
    if body.username:
        username = store.allocate_username(body.username.strip())
    else:
        username = store.allocate_username(_suggest_username_from_email(addr))
    try:
        store.create_user_with_password(
            username=username,
            email=addr,
            phone=None,
            password=body.password,
            email_verified=True,
            phone_verified=False,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    audit_security(request, "auth_register_complete", subject=username, channel="email_otp")
    return {"username": username, "detail": "注册成功，请登录"}


@router.post("/register/email/send-link")
def register_email_send_link(request: Request, body: EmailSendBody) -> dict[str, str]:
    """发送邮箱魔法链接（点击后跳转设置密码页，提交时消耗令牌）。"""
    if not is_valid_email(body.email):
        raise HTTPException(status_code=400, detail="邮箱格式不正确")
    store: IdentityStore = request.app.state.identity_store
    addr = body.email.strip().lower()
    base = _public_base(request)
    raw = store.save_email_verification_link(addr, REGISTER_EMAIL_LINK_PURPOSE, _otp_ttl())
    verify_url = (
        f"{base}/api/v1/auth/register/email/verify-link?"
        + urlencode({"token": raw, "email": addr})
    )
    send_verification_link_email(addr, verify_url, purpose="邮箱注册（链接）")
    if os.environ.get("MASP_EMAIL_LINK_LOG_PLAINTEXT", "").strip() == "1":
        _LOG.warning(
            "[邮箱验证链接明文日志] url=%s（禁止在生产开启）",
            verify_url,
        )
    audit_security(
        request,
        "auth_register_email_link_sent",
        identity_prefix=login_throttle_key(addr)[:16],
    )
    return {"detail": "验证链接已发送（未配置 SMTP 时可设 MASP_EMAIL_LINK_LOG_PLAINTEXT=1 查看 URL）"}


@router.get("/register/email/verify-link", response_model=None)
def register_email_verify_link(
    request: Request,
    token: str = "",
    email: str = "",
) -> RedirectResponse | JSONResponse:
    """校验链接有效性（不消耗令牌）。

    若设置 ``MASP_EMAIL_VERIFY_REDIRECT``，则 302 跳转至该 URL 并附带 ``email``、``token`` 查询参数；
    否则返回 JSON（供客户端调用 ``POST .../complete-link``）。
    """
    tok = token.strip()
    em = email.strip()
    if not tok or not em:
        raise HTTPException(status_code=400, detail="缺少 token 或邮箱")
    if not is_valid_email(em):
        raise HTTPException(status_code=400, detail="邮箱格式不正确")
    addr = em.lower()
    store: IdentityStore = request.app.state.identity_store
    if not store.verify_email_link_token(
        addr, tok, REGISTER_EMAIL_LINK_PURPOSE, consume=False
    ):
        raise HTTPException(status_code=400, detail="链接无效或已过期")
    q = urlencode({"email": addr, "token": tok})
    redir = os.environ.get("MASP_EMAIL_VERIFY_REDIRECT", "").strip().rstrip("/")
    audit_security(
        request,
        "auth_register_email_link_opened",
        identity_prefix=login_throttle_key(addr)[:16],
    )
    if redir:
        return RedirectResponse(f"{redir}?{q}", status_code=302)
    return JSONResponse(
        {
            "status": "verified",
            "email": addr,
            "token": tok,
            "detail": "请使用 POST /api/v1/auth/register/email/complete-link 提交用户名与密码完成注册",
        }
    )


@router.post("/register/email/complete-link")
def register_email_complete_link(
    request: Request, body: EmailLinkCompleteBody
) -> dict[str, str]:
    if not is_valid_email(body.email):
        raise HTTPException(status_code=400, detail="邮箱格式不正确")
    store: IdentityStore = request.app.state.identity_store
    addr = body.email.strip().lower()
    if not store.verify_email_link_token(
        addr,
        body.token.strip(),
        REGISTER_EMAIL_LINK_PURPOSE,
        consume=True,
    ):
        raise HTTPException(status_code=400, detail="链接无效或已使用")
    if body.username:
        username = store.allocate_username(body.username.strip())
    else:
        username = store.allocate_username(_suggest_username_from_email(addr))
    try:
        store.create_user_with_password(
            username=username,
            email=addr,
            phone=None,
            password=body.password,
            email_verified=True,
            phone_verified=False,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    audit_security(request, "auth_register_complete", subject=username, channel="email_link")
    return {"username": username, "detail": "注册成功，请登录"}


@router.post("/register/phone/send")
def register_phone_send(request: Request, body: PhoneSendBody) -> dict[str, str]:
    norm = normalize_phone(body.phone)
    if not norm:
        raise HTTPException(status_code=400, detail="请输入中国大陆 11 位手机号")
    store: IdentityStore = request.app.state.identity_store
    code = f"{secrets.randbelow(900000) + 100000:06d}"
    store.save_verification("phone", norm, code, "register_phone", _otp_ttl())
    send_otp_sms(norm, code, purpose="手机注册")
    audit_security(request, "auth_register_phone_otp_requested", phone_suffix=norm[-4:])
    return {"detail": "验证码已发送（console 后端请开 MASP_OTP_LOG_PLAINTEXT）"}


@router.post("/register/phone/complete")
def register_phone_complete(request: Request, body: PhoneCompleteBody) -> dict[str, str]:
    norm = normalize_phone(body.phone)
    if not norm:
        raise HTTPException(status_code=400, detail="手机号格式不正确")
    store: IdentityStore = request.app.state.identity_store
    if not store.consume_verification("phone", norm, body.code, "register_phone"):
        raise HTTPException(status_code=400, detail="验证码无效或已过期")
    if body.username:
        username = store.allocate_username(body.username.strip())
    else:
        username = store.allocate_username(f"u_{norm[-4:]}")
    try:
        store.create_user_with_password(
            username=username,
            email=None,
            phone=norm,
            password=body.password,
            email_verified=False,
            phone_verified=True,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    audit_security(request, "auth_register_complete", subject=username, channel="phone_otp")
    return {"username": username, "detail": "注册成功，请登录"}


@router.get("/oauth/wechat/url")
def oauth_wechat_url(request: Request) -> dict[str, str]:
    app_id = os.environ.get("MASP_WECHAT_OPEN_APP_ID", "").strip()
    if not app_id:
        raise HTTPException(status_code=503, detail="未配置 MASP_WECHAT_OPEN_APP_ID")
    base = _public_base(request)
    redirect_uri = f"{base}/api/v1/auth/oauth/wechat/callback"
    state = secrets.token_urlsafe(24)
    store: IdentityStore = request.app.state.identity_store
    store.oauth_save_state("wechat", state)
    url = wechat_web_authorize_url(
        app_id=app_id, redirect_uri=redirect_uri, state=state
    )
    return {"authorize_url": url, "state": state}


@router.get("/oauth/wechat/callback", response_model=None)
def oauth_wechat_callback(request: Request, code: str = "", state: str = "") -> JSONResponse:
    if not code or not state:
        return JSONResponse({"error": "缺少 code/state"}, status_code=400)
    store: IdentityStore = request.app.state.identity_store
    if not store.oauth_take_state(state, "wechat"):
        return JSONResponse({"error": "state 无效"}, status_code=400)
    app_id = os.environ.get("MASP_WECHAT_OPEN_APP_ID", "").strip()
    secret = os.environ.get("MASP_WECHAT_OPEN_APP_SECRET", "").strip()
    if not app_id or not secret:
        return JSONResponse({"error": "服务端未配置微信密钥"}, status_code=503)
    try:
        tok = wechat_exchange_code(app_id, secret, code)
        access_token = str(tok["access_token"])
        openid = str(tok["openid"])
        unionid = tok.get("unionid")
        try:
            ui = wechat_userinfo(access_token, openid)
        except Exception:
            ui = {}
        nick = str(ui.get("nickname") or "") or None
        username = store.oauth_bind_or_register(
            "wechat",
            openid,
            str(unionid) if unionid else None,
            nick,
            {"token": tok, "userinfo": ui},
        )
    except Exception as e:
        return JSONResponse({"error": str(e)[:200]}, status_code=400)
    secret_jwt = request.app.state.jwt_secret
    ttl = int(os.environ.get("MASP_JWT_TTL_SEC", "86400"))
    token = issue_access_token(secret_jwt, username, ttl_sec=ttl)
    audit_security(request, "oauth_login_success", provider="wechat", subject=username)
    return JSONResponse(
        {"access_token": token, "token_type": "bearer", "expires_in": ttl, "username": username}
    )


@router.get("/oauth/qq/url")
def oauth_qq_url(request: Request) -> dict[str, str]:
    app_id = os.environ.get("MASP_QQ_APP_ID", "").strip()
    if not app_id:
        raise HTTPException(status_code=503, detail="未配置 MASP_QQ_APP_ID")
    base = _public_base(request)
    redirect_uri = f"{base}/api/v1/auth/oauth/qq/callback"
    state = secrets.token_urlsafe(24)
    store: IdentityStore = request.app.state.identity_store
    store.oauth_save_state("qq", state)
    url = qq_authorize_url(app_id=app_id, redirect_uri=redirect_uri, state=state)
    return {"authorize_url": url, "state": state}


@router.get("/oauth/qq/callback", response_model=None)
def oauth_qq_callback(request: Request, code: str = "", state: str = "") -> JSONResponse:
    if not code or not state:
        return JSONResponse({"error": "缺少 code/state"}, status_code=400)
    store: IdentityStore = request.app.state.identity_store
    if not store.oauth_take_state(state, "qq"):
        return JSONResponse({"error": "state 无效"}, status_code=400)
    app_id = os.environ.get("MASP_QQ_APP_ID", "").strip()
    secret = os.environ.get("MASP_QQ_APP_SECRET", "").strip()
    base = _public_base(request)
    redirect_uri = f"{base}/api/v1/auth/oauth/qq/callback"
    if not app_id or not secret:
        return JSONResponse({"error": "服务端未配置 QQ 密钥"}, status_code=503)
    try:
        tok = qq_exchange_code(app_id, secret, code, redirect_uri)
        access_token = str(tok["access_token"])
        oid = qq_openid(access_token)
        ui = qq_user_info(access_token, app_id, oid)
        nick = str(ui.get("nickname") or "") or None
        username = store.oauth_bind_or_register(
            "qq",
            oid,
            None,
            nick,
            {"token_meta": tok, "userinfo": ui},
        )
    except Exception as e:
        return JSONResponse({"error": str(e)[:200]}, status_code=400)
    secret_jwt = request.app.state.jwt_secret
    ttl = int(os.environ.get("MASP_JWT_TTL_SEC", "86400"))
    token = issue_access_token(secret_jwt, username, ttl_sec=ttl)
    audit_security(request, "oauth_login_success", provider="qq", subject=username)
    return JSONResponse(
        {"access_token": token, "token_type": "bearer", "expires_in": ttl, "username": username}
    )


@router.post("/logout")
def logout(
    request: Request,
    creds: HTTPAuthorizationCredentials = Depends(_bearer_required),
) -> dict[str, bool]:
    secret = request.app.state.jwt_secret
    store: IdentityStore = request.app.state.identity_store
    try:
        payload = decode_access_token(secret, creds.credentials)
    except Exception:
        raise HTTPException(status_code=401, detail="令牌无效") from None
    jti = payload.get("jti")
    exp = payload.get("exp")
    sub = payload.get("sub")
    if jti and isinstance(exp, int):
        store.revoke_token(str(jti), exp)
    audit_security(
        request,
        "auth_logout",
        subject=sub if isinstance(sub, str) else None,
        jti_prefix=str(jti)[:16] if jti else None,
    )
    return {"ok": True}
