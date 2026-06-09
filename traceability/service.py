from __future__ import annotations

from typing import Any, Mapping, Sequence

from mcp_agent_safe_protecter.core.scan_merge import merge_overlay_into_scan_context
from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext
from mcp_agent_safe_protecter.traceability.export_preview import preview_export_audit_report
from mcp_agent_safe_protecter.traceability.models import TraceEventType, TraceSession
from mcp_agent_safe_protecter.traceability.search import fuzzy_match_incidents
from mcp_agent_safe_protecter.traceability.store_sqlite import SQLiteTraceStore
from mcp_agent_safe_protecter.traceability.util import compute_audit_digest


class TraceabilityService:
    """
    溯源业务门面：会话开启、八维事件写入、完整性校验、检索与报告导出。
    可与采集端、网关、审计代理集成；检测结果仍由 ``TraceabilityDetector`` 产出。
    """

    def __init__(self, store: SQLiteTraceStore) -> None:
        self._store = store

    def open_trace(
        self,
        tenant_id: str,
        agent_id: str,
        *,
        meta: Mapping[str, Any] | None = None,
        session_id: str | None = None,
    ) -> str:
        return self._store.create_session(
            tenant_id, agent_id, meta=meta, session_id=session_id
        )

    def record_operation_chain_meta(
        self, session_id: str, meta: Mapping[str, Any]
    ) -> int:
        return self._store.append_event(
            session_id, TraceEventType.OPERATION_CHAIN_META.value, meta
        )

    def record_operation_hop(self, session_id: str, hop: Mapping[str, Any]) -> int:
        return self._store.append_event(
            session_id, TraceEventType.OPERATION_HOP.value, hop
        )

    def record_flow_chain_meta(self, session_id: str, meta: Mapping[str, Any]) -> int:
        return self._store.append_event(
            session_id, TraceEventType.FLOW_CHAIN_META.value, meta
        )

    def record_flow_stage(self, session_id: str, stage: Mapping[str, Any]) -> int:
        return self._store.append_event(
            session_id, TraceEventType.FLOW_STAGE.value, stage
        )

    def record_data_mutation(self, session_id: str, row: Mapping[str, Any]) -> int:
        return self._store.append_event(
            session_id, TraceEventType.DATA_MUTATION.value, row
        )

    def record_asset_soft(self, session_id: str, asset: Mapping[str, Any]) -> int:
        return self._store.append_event(
            session_id, TraceEventType.ASSET_SOFT.value, asset
        )

    def record_asset_hard(self, session_id: str, asset: Mapping[str, Any]) -> int:
        return self._store.append_event(
            session_id, TraceEventType.ASSET_HARD.value, asset
        )

    def record_resource_usage(self, session_id: str, usage: Mapping[str, Any]) -> int:
        return self._store.append_event(
            session_id, TraceEventType.RESOURCE_USAGE.value, usage
        )

    def record_config_change(self, session_id: str, change: Mapping[str, Any]) -> int:
        return self._store.append_event(
            session_id, TraceEventType.CONFIG_CHANGE.value, change
        )

    def record_compliance_audit(self, session_id: str, snapshot: Mapping[str, Any]) -> int:
        return self._store.append_event(
            session_id, TraceEventType.COMPLIANCE_AUDIT.value, snapshot
        )

    def record_error(self, session_id: str, error: Mapping[str, Any]) -> int:
        return self._store.append_event(
            session_id, TraceEventType.ERROR_RECORD.value, error
        )

    def record_threat_event(self, session_id: str, ev: Mapping[str, Any]) -> int:
        return self._store.append_event(
            session_id, TraceEventType.THREAT_EVENT.value, ev
        )

    def record_incident_loop(self, session_id: str, block: Mapping[str, Any]) -> int:
        return self._store.append_event(
            session_id, TraceEventType.INCIDENT_LOOP.value, block
        )

    def append_event(
        self,
        session_id: str,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> int:
        """通用追加入口（HTTP/API 层可直接调用）；event_type 须为 ``TraceEventType`` 取值。"""
        allowed = frozenset(e.value for e in TraceEventType)
        if event_type not in allowed:
            raise ValueError(f"unknown event_type: {event_type!r}")
        return self._store.append_event(session_id, event_type, dict(payload))

    def link_correlation(
        self,
        session_id: str,
        *,
        alert_id: str = "",
        ticket_id: str = "",
        owner_id: str = "",
        **extra: Any,
    ) -> int:
        links: dict[str, Any] = {
            "alert_id": alert_id,
            "ticket_id": ticket_id,
            "owner_id": owner_id,
        }
        links.update(extra)
        return self.record_incident_loop(session_id, {"correlation_links": links})

    def session_meta(self, session_id: str) -> TraceSession | None:
        """返回会话元数据；不存在则 ``None``。"""
        return self._store.get_session(session_id)

    def get_trace_view(self, session_id: str) -> dict[str, Any]:
        return self._store.build_traceability_view(session_id)

    def verify_integrity(self, session_id: str) -> tuple[bool, str]:
        return self._store.verify_chain(session_id)

    def build_scan_context(
        self,
        session_id: str,
        *,
        tenant_id: str = "",
        agent_id: str = "",
        overlay: Mapping[str, Any] | None = None,
    ) -> ScanContext:
        """构造用于安全引擎扫描的上下文：自动挂载会话 ID，可选合并即时 overlay。"""
        sess = self._store.get_session(session_id)
        tid = tenant_id or (sess.tenant_id if sess else "")
        aid = agent_id or (sess.agent_id if sess else "")
        tr: dict[str, Any] = {"session_id": session_id}
        ctx = ScanContext(
            tenant_id=tid,
            agent_id=aid,
            trace_session_id=session_id,
            traceability=tr,
        )
        if overlay:
            ctx = merge_overlay_into_scan_context(ctx, overlay)
        return ctx

    def search_sessions(
        self,
        query: str,
        *,
        tenant_id: str | None = None,
        limit: int = 200,
    ) -> list[TraceSession]:
        sessions = self._store.list_sessions(tenant_id=tenant_id, limit=limit)
        rows: list[dict[str, Any]] = []
        for s in sessions:
            rows.append(
                {
                    "id": s.id,
                    "tenant_id": s.tenant_id,
                    "agent_id": s.agent_id,
                    "title": str(s.meta.get("title", "")),
                    "tags": str(s.meta.get("tags", "")),
                }
            )
        matched = fuzzy_match_incidents(
            query,
            rows,
            keys=("id", "tenant_id", "agent_id", "title", "tags"),
        )
        ids = {str(m["id"]) for m in matched}
        return [s for s in sessions if s.id in ids]

    def generate_report(
        self,
        session_id: str,
        *,
        findings: Sequence[Finding] | None = None,
        redact_export: bool = True,
    ) -> dict[str, Any]:
        view = self._store.build_traceability_view(session_id)
        sess = self._store.get_session(session_id)
        chain_ok, chain_detail = self._store.verify_chain(session_id)
        finding_rows = [
            {"category": f.category, "severity": f.severity.value, "title": f.title}
            for f in (findings or ())
            if f.branch == BranchId.TRACEABILITY
        ]
        bundle = {
            "session_id": session_id,
            "tenant_id": sess.tenant_id if sess else "",
            "agent_id": sess.agent_id if sess else "",
            "traceability": view,
            "integrity": {"chain_ok": chain_ok, "detail": chain_detail},
            "digest": compute_audit_digest({"view": view, "session_id": session_id}),
            "findings_trace_branch": finding_rows,
        }
        if redact_export:
            bundle["export_preview"] = preview_export_audit_report(view)
        return bundle
