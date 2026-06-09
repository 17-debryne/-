from __future__ import annotations

from typing import Any, Mapping, Sequence

from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity
from mcp_agent_safe_protecter.shared.pii import find_pii
from mcp_agent_safe_protecter.traceability.export_preview import preview_export_audit_report
from mcp_agent_safe_protecter.traceability.models import (
    DamageKind,
    ErrorTraceCategory,
    ThreatTraceKind,
    TraceLevel,
)
from mcp_agent_safe_protecter.traceability.search import (
    filter_incidents_by_conditions,
    fuzzy_match_incidents,
)
from mcp_agent_safe_protecter.traceability.store_sqlite import SQLiteTraceStore
from mcp_agent_safe_protecter.traceability.util import (
    assign_trace_level,
    compute_audit_digest,
    merge_traceability_payload,
)


def merged_traceability_view(
    ctx: ScanContext,
    store: SQLiteTraceStore | None = None,
) -> dict[str, Any]:
    """合并持久化会话视图与 ``ScanContext.traceability`` 即时覆盖。"""
    tr_in = dict(ctx.traceability) if ctx.traceability else {}
    sid = (ctx.trace_session_id or str(tr_in.get("session_id") or "")).strip()
    loaded: dict[str, Any] = {}
    if store and sid:
        loaded = store.build_traceability_view(sid)
    if not loaded and not tr_in:
        return {}
    return merge_traceability_payload(loaded, tr_in)


def build_traceability_report_bundle(
    ctx: ScanContext,
    findings: Sequence[Finding],
    *,
    store: SQLiteTraceStore | None = None,
) -> dict[str, Any]:
    """基于合并后的溯源载荷生成报告摘要（完整导出请用 ``TraceabilityService.generate_report``）。"""
    tr = merged_traceability_view(ctx, store)
    keys = [k for k in tr.keys() if k != "session_id"]
    return {
        "generated_at": ctx.now.isoformat(),
        "agent_id": ctx.agent_id,
        "tenant_id": ctx.tenant_id,
        "digest": compute_audit_digest(
            {"traceability": tr, "finding_categories": [f.category for f in findings]}
        ),
        "trace_subsystems": keys,
        "findings_summary": [
            {"category": f.category, "severity": f.severity.value, "title": f.title}
            for f in findings
            if f.branch == BranchId.TRACEABILITY
        ],
    }


class TraceabilityDetector:
    """
    第三项：溯源功能（八个子分支）。
    支持（1）仅内存字典 ``ScanContext.traceability``；（2）``SQLiteTraceStore`` 持久化会话 +
    ``trace_session_id`` / ``session_id`` 自动还原后再检测。
    """

    _CRUD_REQUIRED = frozenset(
        {"op", "old_value", "new_value", "actor", "ts", "trigger", "reason"}
    )

    def __init__(self, store: SQLiteTraceStore | None = None) -> None:
        self._store = store

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        tr = merged_traceability_view(ctx, self._store)
        if not tr:
            return []

        findings: list[Finding] = []
        findings.extend(self._branch1_operation_chain(tr.get("operation_chain") or {}, ctx))
        findings.extend(self._branch2_flow_chain(tr.get("flow_chain") or {}, ctx))
        findings.extend(self._branch3_data_crud(tr.get("data_mutations") or (), ctx))
        findings.extend(self._branch4_asset_resource(tr.get("asset_resources") or {}, ctx))
        findings.extend(self._branch5_compliance(tr.get("compliance_audit") or {}, ctx))
        findings.extend(self._branch6_errors(tr.get("errors") or (), ctx))
        findings.extend(self._branch7_threats(tr.get("threats") or {}, ctx))
        findings.extend(self._branch8_incident_loop(tr.get("incident_loop") or {}, ctx))
        return findings

    def _branch1_operation_chain(self, block: Mapping[str, Any], ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        hops = block.get("hops") or ()
        if not hops:
            return findings

        actors = {str(h.get("actor_type", "")) for h in hops}
        findings.append(
            Finding(
                BranchId.TRACEABILITY,
                "trace_op_chain_summary",
                "操作全链路追溯摘要（人/系统/账号）",
                f"节点数={len(hops)} actor_types={','.join(sorted(actors)) or '未知'}",
                Severity.INFO,
                dict(hop_count=len(hops), actor_types=sorted(actors)),
            )
        )

        for i, h in enumerate(hops):
            if not h.get("principal_id") and not h.get("system_id"):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_op_chain_identity_gap",
                        "操作链路身份标识缺失",
                        f"hop_index={i}",
                        Severity.MEDIUM,
                        dict(h),
                    )
                )
            if h.get("violation_flag"):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_op_chain_violation",
                        "标记为误操作/越权/违规的业务操作节点",
                        str(h.get("detail") or h.get("op")),
                        Severity.HIGH,
                        dict(h),
                    )
                )

        expected_steps = block.get("expected_sequence")
        if (
            isinstance(expected_steps, (list, tuple))
            and expected_steps
            and isinstance(hops, (list, tuple))
        ):
            actual = tuple(h.get("step") for h in hops if isinstance(h, Mapping))
            if tuple(expected_steps) != actual:
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_op_chain_sequence_drift",
                        "操作步骤序列与预期不一致（定位业务误操作）",
                        f"expected={expected_steps} actual={actual}",
                        Severity.MEDIUM,
                        {"expected": list(expected_steps), "actual": list(actual)},
                    )
                )
        return findings

    def _branch2_flow_chain(self, block: Mapping[str, Any], ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        stages = block.get("stages") or ()
        if not stages:
            return findings

        findings.append(
            Finding(
                BranchId.TRACEABILITY,
                "trace_flow_chain_summary",
                "业务/数据/接口流转链路摘要",
                f"阶段数={len(stages)} trace_id={block.get('trace_id', '')}",
                Severity.INFO,
                dict(trace_id=block.get("trace_id"), stage_count=len(stages)),
            )
        )

        for s in stages:
            if s.get("stalled") or (s.get("latency_ms") or 0) > int(
                block.get("latency_budget_ms") or 60_000
            ):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_flow_stall",
                        "流转卡顿或超时",
                        str(s.get("node") or s.get("service")),
                        Severity.MEDIUM,
                        dict(s),
                    )
                )
            if s.get("dropped") or s.get("gap"):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_flow_gap",
                        "丢包、数据断层或链路中断",
                        str(s.get("detail")),
                        Severity.HIGH,
                        dict(s),
                    )
                )
            if s.get("deadlock") or s.get("workflow_stuck"):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_flow_deadlock",
                        "流程卡死或审批流阻塞",
                        str(s.get("node")),
                        Severity.HIGH,
                        dict(s),
                    )
                )
        return findings

    def _branch3_data_crud(self, rows: Sequence[Mapping[str, Any]], ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        if not rows:
            return findings

        findings.append(
            Finding(
                BranchId.TRACEABILITY,
                "trace_crud_summary",
                "数据新增/修改/删除/回滚溯源摘要",
                f"记录数={len(rows)}",
                Severity.INFO,
                {"count": len(rows)},
            )
        )

        for row in rows:
            missing = sorted(self._CRUD_REQUIRED - frozenset(row.keys()))
            if missing:
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_crud_field_gap",
                        "变更溯源字段不完整（原值/新值/变更人/时间/触发源/原因）",
                        ",".join(missing),
                        Severity.MEDIUM,
                        dict(row),
                    )
                )
            if row.get("op") in {"delete", "rollback"} and not row.get("reason"):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_crud_sensitive_without_reason",
                        "删除或回滚缺少变更原因",
                        str(row.get("resource") or row.get("table")),
                        Severity.HIGH,
                        dict(row),
                    )
                )
            if row.get("rollback_ref") and not row.get("rollback_snapshot_ok", True):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_crud_rollback_anomaly",
                        "回滚记录与快照不一致",
                        str(row.get("rollback_ref")),
                        Severity.HIGH,
                        dict(row),
                    )
                )
        return findings

    def _branch4_asset_resource(self, block: Mapping[str, Any], ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        soft = block.get("soft_assets") or ()
        hard = block.get("hard_assets") or ()
        usage = block.get("resource_usage") or ()
        cfg_events = block.get("config_changes") or ()

        if not soft and not hard and not usage and not cfg_events:
            return findings

        findings.append(
            Finding(
                BranchId.TRACEABILITY,
                "trace_asset_summary",
                "资产与资源占用溯源摘要",
                f"软资产={len(soft)} 硬资产={len(hard)} 资源条目={len(usage)} 配置变更={len(cfg_events)}",
                Severity.INFO,
                dict(
                    soft_assets=len(soft),
                    hard_assets=len(hard),
                    resource_usage=len(usage),
                    config_changes=len(cfg_events),
                ),
            )
        )

        for ev in cfg_events:
            if not ev.get("approver") and ev.get("requires_approval", True):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_asset_config_unapproved",
                        "配置变更缺少审批溯源",
                        str(ev.get("path") or ev.get("key")),
                        Severity.MEDIUM,
                        dict(ev),
                    )
                )

        for u in usage:
            cap = float(u.get("quota") or 0)
            cur = float(u.get("current") or 0)
            if cap and cur / cap > float(block.get("quota_warn_ratio") or 0.9):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_asset_quota_pressure",
                        "资源占用逼近或突破配额",
                        str(u.get("resource_id")),
                        Severity.LOW,
                        dict(u),
                    )
                )
        return findings

    def _branch5_compliance(self, block: Mapping[str, Any], ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        if not block:
            return findings

        if block.get("immutable_store") is False:
            findings.append(
                Finding(
                    BranchId.TRACEABILITY,
                    "trace_compliance_mutable_log",
                    "合规溯源日志可被篡改或未写入只增存储",
                    str(block.get("detail")),
                    Severity.HIGH,
                    dict(block),
                )
            )

        if not block.get("archive_record_id"):
            findings.append(
                Finding(
                    BranchId.TRACEABILITY,
                    "trace_compliance_archive_gap",
                    "留痕归档标识缺失",
                    "",
                    Severity.MEDIUM,
                    dict(block),
                )
            )

        if block.get("export_report_supported") is False:
            findings.append(
                Finding(
                    BranchId.TRACEABILITY,
                    "trace_compliance_export_gap",
                    "审计报告导出能力不足",
                    "",
                    Severity.MEDIUM,
                    dict(block),
                )
            )

        ts_chain = block.get("timestamp_chain_ok")
        if ts_chain is False:
            findings.append(
                Finding(
                    BranchId.TRACEABILITY,
                    "trace_compliance_timestamp_break",
                    "时间戳链校验失败（防伪/可信时间源）",
                    str(block.get("detail")),
                    Severity.HIGH,
                    dict(block),
                )
            )

        redacted = block.get("redaction_applied", True)
        sample = str(block.get("sample_line") or "")
        if sample and not redacted and find_pii(sample):
            findings.append(
                Finding(
                    BranchId.TRACEABILITY,
                    "trace_compliance_pii_leak",
                    "脱敏留痕未生效且样本含敏感信息",
                    "",
                    Severity.HIGH,
                    {"pii_hits": [m.kind for m in find_pii(sample)]},
                )
            )

        findings.append(
            Finding(
                BranchId.TRACEABILITY,
                "trace_compliance_digest",
                "合规溯源摘要指纹",
                compute_audit_digest(block)[:16] + "…",
                Severity.INFO,
                {"digest": compute_audit_digest(block)},
            )
        )
        return findings

    def _branch6_errors(self, errors: Sequence[Mapping[str, Any]], ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        if not errors:
            return findings

        for err in errors:
            cat = str(err.get("category") or "")
            try:
                ErrorTraceCategory(cat)
            except ValueError:
                if cat:
                    findings.append(
                        Finding(
                            BranchId.TRACEABILITY,
                            "trace_error_bad_category",
                            "错误分类不在约定集合（system/business/code/config）",
                            cat,
                            Severity.LOW,
                            dict(err),
                        )
                    )

            if err.get("message") and not err.get("stack"):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_error_stack_gap",
                        "错误溯源缺少上下文堆栈",
                        str(err.get("message"))[:200],
                        Severity.MEDIUM,
                        dict(err),
                    )
                )

            if err.get("capture_io") and (
                err.get("request_payload") is None and err.get("response_payload") is None
            ):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_error_io_gap",
                        "未记录入参/出参用于错误复现",
                        str(err.get("endpoint") or ""),
                        Severity.MEDIUM,
                        dict(err),
                    )
                )

            if err.get("capture_env") and not err.get("env_fingerprint"):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_error_env_gap",
                        "环境变量溯源字段缺失",
                        "",
                        Severity.LOW,
                        dict(err),
                    )
                )

            if not err.get("repro_steps") and err.get("require_repro", True):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_error_repro_gap",
                        "缺少复现条件与操作路径溯源",
                        str(err.get("message") or "")[:120],
                        Severity.MEDIUM,
                        dict(err),
                    )
                )

        return findings

    def _branch7_threats(self, block: Mapping[str, Any], ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        events = block.get("events") or ()
        if not events:
            return findings

        for ev in events:
            kind = str(ev.get("kind") or "")
            try:
                ThreatTraceKind(kind)
            except ValueError:
                if kind:
                    findings.append(
                        Finding(
                            BranchId.TRACEABILITY,
                            "trace_threat_kind_unknown",
                            "威胁分类不在约定集合",
                            kind,
                            Severity.LOW,
                            dict(ev),
                        )
                    )

            if not ev.get("source_ip") and ev.get("need_attribution", True):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_threat_src_gap",
                        "攻击源 IP / 归属缺失",
                        str(ev.get("id")),
                        Severity.MEDIUM,
                        dict(ev),
                    )
                )

            if not ev.get("behavior_signature"):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_threat_behavior_gap",
                        "行为特征未结构化记录",
                        str(ev.get("id")),
                        Severity.LOW,
                        dict(ev),
                    )
                )

            path = ev.get("lateral_path") or ()
            if ev.get("lateral_movement_suspected") and len(path) < 2:
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_threat_lateral_gap",
                        "横向移动疑似但入侵路径不完整",
                        "",
                        Severity.HIGH,
                        dict(ev),
                    )
                )

            aff = ev.get("affected_assets") or ()
            if not aff:
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_threat_impact_gap",
                        "影响资产全链路未闭环",
                        str(ev.get("id")),
                        Severity.MEDIUM,
                        dict(ev),
                    )
                )

            spread = ev.get("diffusion_trace") or ()
            if ev.get("diffusion_expected") and not spread:
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_threat_diffusion_gap",
                        "威胁扩散轨迹溯源缺失",
                        "",
                        Severity.HIGH,
                        dict(ev),
                    )
                )

            if ev.get("origin_trace_incomplete"):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_threat_origin_gap",
                        "威胁源头追踪未完成",
                        str(ev.get("detail")),
                        Severity.HIGH,
                        dict(ev),
                    )
                )

            if ev.get("auto_response_recorded") is False:
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_threat_response_gap",
                        "威胁处置未记录或未联动封禁/告警",
                        str(ev.get("id")),
                        Severity.HIGH,
                        dict(ev),
                    )
                )

        return findings

    def _branch8_incident_loop(self, block: Mapping[str, Any], ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        if not block:
            return findings

        damage = str(block.get("damage_kind") or "")
        if damage:
            try:
                DamageKind(damage)
            except ValueError:
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_loop_damage_kind_unknown",
                        "损坏类型不在 hardware/software/link/human",
                        damage,
                        Severity.LOW,
                        dict(block),
                    )
                )

        level_raw = block.get("trace_level") or block.get("severity_level")
        if level_raw is not None:
            try:
                TraceLevel(int(level_raw))
            except (ValueError, TypeError):
                findings.append(
                    Finding(
                        BranchId.TRACEABILITY,
                        "trace_loop_level_invalid",
                        "溯源等级应为 1-4",
                        str(level_raw),
                        Severity.MEDIUM,
                        dict(block),
                    )
                )

        if block.get("fuzzy_search_supported") is False:
            findings.append(
                Finding(
                    BranchId.TRACEABILITY,
                    "trace_loop_search_gap",
                    "未启用模糊检索能力",
                    "",
                    Severity.LOW,
                    dict(block),
                )
            )

        if block.get("one_click_replay_supported") is False:
            findings.append(
                Finding(
                    BranchId.TRACEABILITY,
                    "trace_loop_replay_gap",
                    "一键复盘能力不足",
                    "",
                    Severity.MEDIUM,
                    dict(block),
                )
            )

        if block.get("auto_report_supported") is False:
            findings.append(
                Finding(
                    BranchId.TRACEABILITY,
                    "trace_loop_report_gap",
                    "自动生成溯源报告未启用",
                    "",
                    Severity.MEDIUM,
                    dict(block),
                )
            )

        links = block.get("correlation_links") or {}
        required = ("alert_id", "ticket_id", "owner_id")
        missing = [k for k in required if not links.get(k)]
        if block.get("require_correlation", True) and missing:
            findings.append(
                Finding(
                    BranchId.TRACEABILITY,
                    "trace_loop_correlation_gap",
                    "溯源触发后未关联报警、工单或责任人推送",
                    ",".join(missing),
                    Severity.HIGH,
                    dict(links),
                )
            )

        findings.append(
            Finding(
                BranchId.TRACEABILITY,
                "trace_loop_summary",
                "循环溯源与复盘能力摘要",
                f"level={level_raw} damage={damage or 'n/a'}",
                Severity.INFO,
                dict(block),
            )
        )
        return findings
