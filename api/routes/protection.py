from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from mcp_agent_safe_protecter.api.deps import AuthPrincipal, require_auth
from mcp_agent_safe_protecter.protection.context import ProtectionEvaluationContext
from mcp_agent_safe_protecter.protection.engine import ProtectionEngine
from mcp_agent_safe_protecter.protection.types import ProtectionBranchId, ProtectionSignal
from mcp_agent_safe_protecter.traceability.service import TraceabilityService

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}", tags=["protection"])


def _svc(request: Request, tenant_id: str) -> TraceabilityService:
    registry = request.app.state.registry
    store = registry.get_store(tenant_id)
    return TraceabilityService(store)


def _signal_dict(sig: ProtectionSignal) -> dict[str, Any]:
    return {
        "branch": sig.branch.value,
        "category": sig.category,
        "title": sig.title,
        "detail": sig.detail,
        "severity": sig.severity.value,
        "evidence": dict(sig.evidence),
        "recommended_enforcement": list(sig.recommended_enforcement),
        "detected_at": sig.detected_at.isoformat(),
    }


class ProtectionEvaluateBody(BaseModel):
    overlay: dict[str, Any] = Field(default_factory=dict)
    enabled_branches: list[str] | None = Field(
        default=None,
        description="防护分支 ProtectionBranchId，省略则评估全部七项。",
    )


@router.post("/sessions/{session_id}/protection/evaluate")
def evaluate_protection(
    request: Request,
    tenant_id: str,
    session_id: str,
    body: ProtectionEvaluateBody | None = None,
    _auth: AuthPrincipal = Depends(require_auth),
) -> dict[str, Any]:
    _ = _auth
    svc = _svc(request, tenant_id)
    if svc.session_meta(session_id) is None:
        raise HTTPException(status_code=404, detail="会话不存在")

    body = body or ProtectionEvaluateBody()
    enabled: frozenset[ProtectionBranchId] | None = None
    if body.enabled_branches:
        try:
            enabled = frozenset(ProtectionBranchId(b) for b in body.enabled_branches)
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"enabled_branches 非法，须为 ProtectionBranchId: {e}",
            ) from e

    scan_ctx = svc.build_scan_context(
        session_id,
        tenant_id=tenant_id,
        overlay=body.overlay or None,
    )
    pctx = ProtectionEvaluationContext.from_scan(scan_ctx)
    engine = ProtectionEngine()
    t0 = time.perf_counter()
    signals = engine.run(pctx, enabled_branches=enabled)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    should_block = any(sig.severity.value in ("high", "critical") for sig in signals)

    return {
        "signals": [_signal_dict(s) for s in signals],
        "summary": {
            "signal_count": len(signals),
            "should_block_heuristic": should_block,
            "elapsed_ms": round(elapsed_ms, 3),
            "enabled_branches": [b.value for b in enabled] if enabled else None,
        },
    }
