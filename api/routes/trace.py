from __future__ import annotations

import json
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from mcp_agent_safe_protecter.api.deps import AuthPrincipal, require_auth
from mcp_agent_safe_protecter.api.metrics_prom import observe_evaluate_completed
from mcp_agent_safe_protecter.api.export_service import write_trace_export
from mcp_agent_safe_protecter.branches.self_trust import SelfCheckMode
from mcp_agent_safe_protecter.branches.traceability import TraceabilityDetector
from mcp_agent_safe_protecter.core.types import BranchId, Finding, Severity
from mcp_agent_safe_protecter.engine import SecurityDetectionEngine
from mcp_agent_safe_protecter.traceability.service import TraceabilityService

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}", tags=["traceability"])


def _svc(request: Request, tenant_id: str) -> TraceabilityService:
    registry = request.app.state.registry
    store = registry.get_store(tenant_id)
    return TraceabilityService(store)


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "branch": f.branch.value,
        "category": f.category,
        "title": f.title,
        "detail": f.detail,
        "severity": f.severity.value,
        "evidence": dict(f.evidence),
        "detected_at": f.detected_at.isoformat(),
    }


class CreateSessionBody(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=256)
    meta: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = Field(default=None, max_length=128)


class AppendEventBody(BaseModel):
    event_type: str = Field(..., min_length=1, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)


class ScanBody(BaseModel):
    """扫描请求：overlay 可携带与各 ``ScanContext`` 字段同名的 JSON（含 metrics、tool_calls 等）。"""

    overlay: dict[str, Any] = Field(default_factory=dict)
    enabled_branches: list[str] | None = Field(
        default=None,
        description="仅运行列出的检测分支（BranchId 枚举值）。省略则运行全部。",
    )
    self_check_mode: Literal["periodic", "triggered"] | None = Field(
        default=None,
        description="分支四自检模式：periodic=周期性自检；triggered=触发式（默认）。",
    )


class ExportFileBody(BaseModel):
    redact: bool = True


@router.get("/quota")
def tenant_quota_summary(
    request: Request,
    tenant_id: str,
    _auth: AuthPrincipal = Depends(require_auth),
) -> dict[str, Any]:
    _ = _auth
    qm = request.app.state.quota_manager
    registry = request.app.state.registry
    store = registry.get_store(tenant_id)
    lim = qm.limits_for(tenant_id)
    return {
        "tenant_id": tenant_id,
        "limits": {
            "max_sessions": lim.max_sessions,
            "max_events_per_session": lim.max_events_per_session,
            "max_export_bytes_per_day": lim.max_export_bytes_per_day,
        },
        "usage": {
            "sessions": store.count_sessions(),
            "export_bytes_today": qm.export_bytes_used_today(tenant_id),
        },
    }


@router.post("/sessions")
def create_session(
    request: Request,
    tenant_id: str,
    body: CreateSessionBody,
    auth: AuthPrincipal = Depends(require_auth),
) -> dict[str, Any]:
    _ = auth
    registry = request.app.state.registry
    store = registry.get_store(tenant_id)
    qm = request.app.state.quota_manager
    if not qm.allow_new_session(tenant_id, store):
        raise HTTPException(status_code=429, detail="租户会话数量已达配额上限")
    svc = TraceabilityService(store)
    sid = svc.open_trace(
        tenant_id,
        body.agent_id,
        meta=body.meta,
        session_id=body.session_id,
    )
    return {"session_id": sid}


@router.get("/sessions")
def list_sessions(
    request: Request,
    tenant_id: str,
    q: str = Query("", max_length=256),
    limit: int = Query(200, ge=1, le=2000),
    auth: AuthPrincipal = Depends(require_auth),
) -> dict[str, Any]:
    _ = auth
    svc = _svc(request, tenant_id)
    sessions = svc.search_sessions(q, tenant_id=tenant_id, limit=limit)
    return {
        "sessions": [
            {
                "id": s.id,
                "tenant_id": s.tenant_id,
                "agent_id": s.agent_id,
                "created_at": _iso_utc(s.created_at),
                "meta": s.meta,
            }
            for s in sessions
        ]
    }


def _iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        return dt.isoformat() + "Z"
    return dt.astimezone().isoformat()


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@router.get("/sessions/{session_id}")
def get_session(
    request: Request,
    tenant_id: str,
    session_id: str,
    auth: AuthPrincipal = Depends(require_auth),
) -> dict[str, Any]:
    _ = auth
    svc = _svc(request, tenant_id)
    sess = svc.session_meta(session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail="会话不存在")
    return {
        "id": sess.id,
        "tenant_id": sess.tenant_id,
        "agent_id": sess.agent_id,
        "created_at": _iso_utc(sess.created_at),
        "meta": sess.meta,
    }


@router.get("/sessions/{session_id}/view")
def get_trace_view(
    request: Request,
    tenant_id: str,
    session_id: str,
    auth: AuthPrincipal = Depends(require_auth),
) -> dict[str, Any]:
    _ = auth
    svc = _svc(request, tenant_id)
    if svc.session_meta(session_id) is None:
        raise HTTPException(status_code=404, detail="会话不存在")
    return {"traceability": svc.get_trace_view(session_id)}


@router.get("/sessions/{session_id}/integrity")
def verify_integrity(
    request: Request,
    tenant_id: str,
    session_id: str,
    auth: AuthPrincipal = Depends(require_auth),
) -> dict[str, Any]:
    _ = auth
    svc = _svc(request, tenant_id)
    if svc.session_meta(session_id) is None:
        raise HTTPException(status_code=404, detail="会话不存在")
    ok, detail = svc.verify_integrity(session_id)
    return {"chain_ok": ok, "detail": detail}


@router.post("/sessions/{session_id}/events")
def append_event(
    request: Request,
    tenant_id: str,
    session_id: str,
    body: AppendEventBody,
    auth: AuthPrincipal = Depends(require_auth),
) -> dict[str, Any]:
    _ = auth
    registry = request.app.state.registry
    store = registry.get_store(tenant_id)
    qm = request.app.state.quota_manager
    svc = TraceabilityService(store)
    if svc.session_meta(session_id) is None:
        raise HTTPException(status_code=404, detail="会话不存在")
    if not qm.allow_append_event(tenant_id, store, session_id):
        raise HTTPException(status_code=429, detail="本会话事件条数已达配额上限")
    try:
        seq = svc.append_event(session_id, body.event_type, body.payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"seq": seq}


@router.post("/sessions/{session_id}/scan")
def run_scan(
    request: Request,
    tenant_id: str,
    session_id: str,
    body: ScanBody | None = None,
    auth: AuthPrincipal = Depends(require_auth),
) -> dict[str, Any]:
    _ = auth
    svc = _svc(request, tenant_id)
    if svc.session_meta(session_id) is None:
        raise HTTPException(status_code=404, detail="会话不存在")

    store = request.app.state.registry.get_store(tenant_id)
    det = TraceabilityDetector(store=store)
    body = body or ScanBody()
    enabled: frozenset[BranchId] | None = None
    if body.enabled_branches:
        try:
            enabled = frozenset(BranchId(b) for b in body.enabled_branches)
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"enabled_branches 含非法值，须为 BranchId 字符串: {e}",
            ) from e
    engine = SecurityDetectionEngine(traceability=det, enabled_branches=enabled)
    overlay = body.overlay
    ctx = svc.build_scan_context(
        session_id,
        tenant_id=tenant_id,
        overlay=overlay or None,
    )
    scm = (
        SelfCheckMode.PERIODIC
        if body.self_check_mode == "periodic"
        else SelfCheckMode.TRIGGERED
    )
    started_at = _iso_utc_now()
    t0 = time.perf_counter()
    findings = engine.run(ctx, self_check_mode=scm)
    elapsed = time.perf_counter() - t0
    ended_at = _iso_utc_now()
    blocked = any(f.severity == Severity.CRITICAL for f in findings)
    observe_evaluate_completed(elapsed, blocked)
    self_heal = any(f.branch == BranchId.EMERGENCY_SELF_HEAL for f in findings)
    audit = getattr(request.app.state, "audit_store", None)
    if audit is not None:
        sess = svc.session_meta(session_id)
        ov = overlay or {}
        summary = {
            "finding_count": len(findings),
            "by_severity": dict(Counter(f.severity.value for f in findings)),
            "blocked_heuristic": blocked,
        }
        audit.record_evaluation(
            trace_session_id=session_id,
            tenant_id=tenant_id,
            agent_id=sess.agent_id if sess else "",
            started_at=started_at,
            ended_at=ended_at,
            blocked=blocked,
            self_heal_triggered=self_heal,
            protection_summary=summary,
            context_snapshot={
                "overlay_keys": sorted(ov.keys()),
                "enabled_branches": list(body.enabled_branches)
                if body.enabled_branches
                else None,
                "self_check_mode": body.self_check_mode,
            },
            findings=findings,
            trace_artifact=svc.get_trace_view(session_id),
        )
    return {
        "findings": [_finding_dict(f) for f in findings],
        "trace_findings": [
            _finding_dict(f) for f in findings if f.branch == BranchId.TRACEABILITY
        ],
        "scan": {
            "enabled_branches": [b.value for b in enabled] if enabled else None,
            "self_check_mode": body.self_check_mode or "triggered",
        },
    }


@router.get("/sessions/{session_id}/report")
def get_report(
    request: Request,
    tenant_id: str,
    session_id: str,
    redact: bool = Query(True),
    auth: AuthPrincipal = Depends(require_auth),
) -> dict[str, Any]:
    _ = auth
    svc = _svc(request, tenant_id)
    if svc.session_meta(session_id) is None:
        raise HTTPException(status_code=404, detail="会话不存在")
    return svc.generate_report(session_id, findings=None, redact_export=redact)


@router.post("/sessions/{session_id}/export/file")
def export_report_file(
    request: Request,
    tenant_id: str,
    session_id: str,
    body: ExportFileBody | None = None,
    auth: AuthPrincipal = Depends(require_auth),
) -> dict[str, Any]:
    svc = _svc(request, tenant_id)
    if svc.session_meta(session_id) is None:
        raise HTTPException(status_code=404, detail="会话不存在")

    redact = body.redact if body else True
    report = svc.generate_report(session_id, findings=None, redact_export=redact)
    blob = json.dumps(report, ensure_ascii=False, default=str).encode("utf-8")

    qm = request.app.state.quota_manager
    if not qm.allow_export(tenant_id, len(blob)):
        raise HTTPException(status_code=429, detail="超出租户每日导出字节配额")

    export_root = request.app.state.export_root
    audit = request.app.state.export_audit
    fname, _path, nbytes = write_trace_export(
        export_root=export_root,
        tenant_id=tenant_id,
        session_id=session_id,
        principal=auth.subject,
        payload=report,
        audit=audit,
    )
    qm.record_export(tenant_id, nbytes)
    return {
        "filename": fname,
        "bytes": nbytes,
        "tenant_id": tenant_id,
        "exported_by": auth.subject,
    }
