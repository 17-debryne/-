from __future__ import annotations

import hashlib
import hmac
import os
import time

from starlette.requests import Request


def verify_admin_hmac(request: Request, secret: str) -> bool:
    """
    校验管理请求 HMAC：hex(HMAC-SHA256(secret, "{ts}\\n{METHOD}\\n{path}"))；
    ``path`` 不含 querystring；时钟偏差见 ``MASP_ADMIN_HMAC_MAX_SKEW_SEC``。
    """
    ts_raw = request.headers.get("x-masp-timestamp", "").strip()
    sig = request.headers.get("x-masp-signature", "").strip().lower()
    if not ts_raw or not sig:
        return False
    try:
        ts = int(ts_raw)
    except ValueError:
        return False
    skew = int(os.environ.get("MASP_ADMIN_HMAC_MAX_SKEW_SEC", "120"))
    now = int(time.time())
    if abs(now - ts) > skew:
        return False
    path = request.url.path
    msg = f"{ts}\n{request.method.upper()}\n{path}".encode("utf-8")
    mac = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, sig)
