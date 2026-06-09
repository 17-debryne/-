from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from mcp_agent_safe_protecter.api.app_database import AppDatabase
from mcp_agent_safe_protecter.api.deps import require_auth
from mcp_agent_safe_protecter.api.export_service import ExportAuditLog
from mcp_agent_safe_protecter.api.health_detail import health_checks
from mcp_agent_safe_protecter.api.jwt_util import resolve_jwt_secret
from mcp_agent_safe_protecter.api.middleware_security import (
    RateLimitMiddleware,
    RequestIdMiddleware,
)
from mcp_agent_safe_protecter.api.policy_integrity import verify_quotas_json_hmac_if_configured
from mcp_agent_safe_protecter.api.quota_manager import QuotaManager, resolve_export_root
from mcp_agent_safe_protecter.api.security_audit import SecurityAuditLog
from mcp_agent_safe_protecter.api.routes.admin_cache import router as admin_cache_router
from mcp_agent_safe_protecter.api.routes.auth import router as auth_router
from mcp_agent_safe_protecter.api.routes.auth_identity import router as identity_auth_router
from mcp_agent_safe_protecter.api.routes.protection import router as protection_router
from mcp_agent_safe_protecter.api.routes.trace import router as trace_router
from mcp_agent_safe_protecter.api.tenant_registry import TenantTraceRegistry
from mcp_agent_safe_protecter.api.user_store import UserStore
from mcp_agent_safe_protecter.audit.paths import resolve_audit_database_path
from mcp_agent_safe_protecter.audit.store import AuditSQLiteStore
from mcp_agent_safe_protecter.identity.auth_paths import resolve_auth_database_path
from mcp_agent_safe_protecter.identity.store import IdentityStore

AppMode = Literal["full", "auth", "core"]

WEB_ROOT = Path(__file__).resolve().parent.parent / "web"


def _make_lifespan(
    *,
    base: Path,
    reg: TenantTraceRegistry | None,
    mode: AppMode,
):
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.registry = reg
        app.state.data_dir = base
        app.state.jwt_secret = resolve_jwt_secret(base)

        app_db = AppDatabase(base / "masp_app.sqlite3")
        app.state.app_db = app_db
        app.state.security_audit = SecurityAuditLog(base)
        verify_quotas_json_hmac_if_configured(base / "tenant_quotas.json")
        app_db.migrate_quotas_from_json(base / "tenant_quotas.json")
        app_db.migrate_legacy_users_from_json(base / "auth" / "users.json")
        app_db.prune_old_export_usage()

        app.state.user_store = UserStore(base / "auth", app_db)
        app.state.user_store.ensure_bootstrap()
        auth_db_path = resolve_auth_database_path(base)
        app.state.identity_store = IdentityStore(auth_db_path)
        app.state.identity_store.prune_ephemeral()
        app.state.identity_store.ensure_bootstrap_admin()

        if mode != "auth":
            app.state.quota_manager = QuotaManager(app_db)
            app.state.export_root = resolve_export_root(base)
            app.state.export_audit = ExportAuditLog(base)
            app.state.audit_store = AuditSQLiteStore(resolve_audit_database_path(base))
        else:
            app.state.quota_manager = None
            app.state.export_root = Path(base) / "exports"
            app.state.export_audit = None
            app.state.audit_store = None

        try:
            yield
        finally:
            if reg is not None:
                reg.close_all()
            app.state.identity_store.close()
            aud = getattr(app.state, "audit_store", None)
            if aud is not None:
                aud.close()
            app_db.close()

    return lifespan


def create_app(
    *,
    data_dir: str | Path | None = None,
    registry: TenantTraceRegistry | None = None,
    mode: AppMode = "full",
) -> FastAPI:
    """
    ``full``：默认单体（溯源 API + 认证）；若存在 ``web/`` 静态资源则挂载 ``/ui``。
    ``auth``：仅认证与注册相关路由（独立容器）。
    ``core``：溯源等业务 API，不含登录注册路由（独立容器，需与 ``auth`` 共享 ``MASP_DATA_DIR`` 卷）。
    """
    if registry is not None:
        base = Path(registry.data_dir)
    else:
        base = Path(data_dir or os.environ.get("MASP_DATA_DIR", "./var/masp"))
    base.mkdir(parents=True, exist_ok=True)

    reg: TenantTraceRegistry | None = None
    if mode != "auth":
        reg = registry if registry is not None else TenantTraceRegistry(base)

    titles = {
        "full": "MCP Agent Safe Protecter",
        "auth": "MASP Auth Service",
        "core": "MASP Core API",
    }
    app = FastAPI(title=titles.get(mode, "MASP"), lifespan=_make_lifespan(base=base, reg=reg, mode=mode))

    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(RateLimitMiddleware)

    origins = os.environ.get("MASP_CORS_ORIGINS", "*").strip()
    allow = ["*"] if origins == "*" else [o.strip() for o in origins.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if mode in ("full", "auth"):
        app.include_router(auth_router)
        app.include_router(identity_auth_router)
    if mode in ("full", "core"):
        app.include_router(trace_router)
        app.include_router(protection_router)
        app.include_router(admin_cache_router)

    @app.get("/health")
    def health(request: Request) -> dict[str, Any]:
        detail = health_checks(request, base=base)
        return {
            "status": detail["health_status"],
            "mode": mode,
            **detail,
        }

    if mode in ("full", "core"):

        @app.get("/metrics")
        def prometheus_metrics() -> Any:
            from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
            from starlette.responses import Response

            return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

        @app.get("/api/v1/meta")
        async def meta(
            request: Request,
            _auth: Any = Depends(require_auth),
        ) -> dict[str, Any]:
            _ = _auth
            export_root = getattr(request.app.state, "export_root", base / "exports")
            reg_dir = reg.data_dir.resolve() if reg is not None else base.resolve()
            app_db_path = getattr(request.app.state, "app_db", None)
            ident = getattr(request.app.state, "identity_store", None)
            aud = getattr(request.app.state, "audit_store", None)
            return {
                "name": "mcp-agent-safe-protecter",
                "mode": mode,
                "multi_tenant_db": True,
                "jwt_login": True,
                "data_dir": str(reg_dir),
                "export_dir": str(Path(export_root).resolve()),
                "app_database": str(app_db_path.path.resolve())
                if app_db_path is not None
                else None,
                "auth_database": str(ident.database_path.resolve())
                if ident is not None
                else None,
                "audit_database": str(aud.database_path.resolve())
                if aud is not None
                else None,
            }

    if mode == "full" and WEB_ROOT.is_dir() and any(WEB_ROOT.iterdir()):
        app.mount("/ui", StaticFiles(directory=str(WEB_ROOT), html=True), name="web_ui")

        @app.get("/")
        def root_to_console() -> RedirectResponse:
            return RedirectResponse(url="/ui/browser-console.html")

    return app
