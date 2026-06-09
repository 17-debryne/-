from __future__ import annotations

import os
import threading
import time
import uuid
from collections import defaultdict
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


def _client_ip(request: Request) -> str:
    if os.environ.get("MASP_TRUST_X_FORWARDED_FOR", "").strip() == "1":
        xff = request.headers.get("x-forwarded-for", "").strip()
        if xff:
            return xff.split(",")[0].strip()[:128]
    if request.client:
        return request.client.host
    return "unknown"


class RequestIdMiddleware(BaseHTTPMiddleware):
    """注入 ``request.state.request_id``，响应头 ``X-Request-Id``。"""

    HEADER = "X-Request-Id"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        incoming = request.headers.get(self.HEADER.lower()) or request.headers.get(
            self.HEADER
        )
        rid = (incoming or "").strip() or str(uuid.uuid4())
        request.state.request_id = rid
        resp = await call_next(request)
        resp.headers[self.HEADER] = rid
        return resp


class _MinuteWindowLimiter:
    """固定 60 秒窗口计数（线程安全）。"""

    def __init__(self, max_hits: int) -> None:
        self.max_hits = max_hits
        self._lock = threading.Lock()
        self._window_start = int(time.time()) // 60
        self._counts: defaultdict[str, int] = defaultdict(int)

    def allow(self, key: str) -> bool:
        if self.max_hits <= 0:
            return True
        now_w = int(time.time()) // 60
        with self._lock:
            if now_w != self._window_start:
                self._counts.clear()
                self._window_start = now_w
            if self._counts[key] >= self.max_hits:
                return False
            self._counts[key] += 1
            return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    按客户端 IP 限流（可选信任 ``X-Forwarded-For``）。

    - ``MASP_RATE_LIMIT_AUTH_PER_MINUTE``：``/api/v1/auth/login``、``/api/v1/auth/register`` 前缀等。
    - ``MASP_RATE_LIMIT_ADMIN_PER_MINUTE``：``/api/v1/admin/``。
    设为 ``0`` 关闭对应桶。
    """

    def __init__(self, app: Callable) -> None:
        super().__init__(app)
        auth_n = int(os.environ.get("MASP_RATE_LIMIT_AUTH_PER_MINUTE", "60"))
        admin_n = int(os.environ.get("MASP_RATE_LIMIT_ADMIN_PER_MINUTE", "120"))
        self._auth = _MinuteWindowLimiter(auth_n)
        self._admin = _MinuteWindowLimiter(admin_n)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path
        ip = _client_ip(request)
        if path.startswith("/api/v1/admin/"):
            if not self._admin.allow(f"admin:{ip}"):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "管理接口请求过于频繁，请稍后重试"},
                )
        if path.startswith("/api/v1/auth/register") or path == "/api/v1/auth/login":
            if not self._auth.allow(f"auth:{ip}"):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "认证接口请求过于频繁，请稍后重试"},
                )
        return await call_next(request)
