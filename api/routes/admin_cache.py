from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from mcp_agent_safe_protecter.api.deps import AuthPrincipal, require_admin_access
from mcp_agent_safe_protecter.api.security_audit import audit_security

router = APIRouter(prefix="/api/v1/admin/cache", tags=["admin-cache"])

CacheScope = Literal["trace_stores"]


class CacheCleanupBody(BaseModel):
    """清理服务端内存缓存（当前实现：租户溯源 SQLite 连接缓存）。"""

    tenant_ids: list[str] | None = Field(
        default=None,
        description="要驱逐的租户 ID；省略或空列表表示驱逐全部已缓存连接",
    )
    checkpoint_wal: bool = Field(
        default=True,
        description="驱逐前对各租户库执行 PRAGMA wal_checkpoint",
    )
    scopes: list[CacheScope] = Field(
        default_factory=lambda: ["trace_stores"],
        description="清理范围，当前仅支持 trace_stores",
    )


@router.get("/stats")
def cache_stats(
    request: Request,
    _auth: AuthPrincipal = Depends(require_admin_access),
) -> dict[str, Any]:
    _ = _auth
    reg = getattr(request.app.state, "registry", None)
    if reg is None:
        raise HTTPException(status_code=503, detail="当前进程未挂载租户溯源注册表")
    return {"components": [reg.trace_store_cache_stats()]}


@router.post("/cleanup")
def cache_cleanup(
    request: Request,
    body: CacheCleanupBody,
    _auth: AuthPrincipal = Depends(require_admin_access),
) -> dict[str, Any]:
    _ = _auth
    reg = getattr(request.app.state, "registry", None)
    if reg is None:
        raise HTTPException(status_code=503, detail="当前进程未挂载租户溯源注册表")

    results: list[dict[str, Any]] = []
    if "trace_stores" in body.scopes:
        tids = body.tenant_ids
        if tids is not None and len(tids) == 0:
            tids = None
        results.append(
            reg.evict_trace_store_cache(tids, checkpoint_wal=body.checkpoint_wal)
        )

    audit_security(
        request,
        "admin_cache_cleanup",
        principal=_auth.subject,
        scopes=body.scopes,
        checkpoint_wal=body.checkpoint_wal,
        tenant_ids=body.tenant_ids,
        evicted=[r.get("evicted_tenant_ids") for r in results],
    )
    return {"ok": True, "results": results}
