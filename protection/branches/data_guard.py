from __future__ import annotations

from mcp_agent_safe_protecter.core.types import Severity
from mcp_agent_safe_protecter.protection.context import ProtectionEvaluationContext
from mcp_agent_safe_protecter.protection.types import ProtectionBranchId, ProtectionSignal
from mcp_agent_safe_protecter.shared.pii import find_pii


class DataGuardProtection:
    """
    分支⑥ 数据安全防护。
    防泄露、防敏感外传、非法导出；隐私违规输出；知识库防爬取与防篡改；防非法读取。
    """

    def analyze(self, ctx: ProtectionEvaluationContext) -> list[ProtectionSignal]:
        s: list[ProtectionSignal] = []
        sc = ctx.scan
        dg = sc.self_check.get("data_guard") or {}

        if isinstance(dg, dict):
            if dg.get("export_blocked"):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.DATA_GUARD,
                        "export_block",
                        "非法导出已被 DLP 阻断",
                        str(dg.get("target", "")),
                        Severity.HIGH,
                        dict(dg),
                        ("reject_request",),
                    )
                )
            if dg.get("kb_crawl_blocked"):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.DATA_GUARD,
                        "kb_crawl_guard",
                        "知识库批量爬取已拦截",
                        str(dg.get("source", "")),
                        Severity.HIGH,
                        dict(dg),
                        ("reject_request", "block_tool"),
                    )
                )
            if dg.get("kb_write_tamper_blocked"):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.DATA_GUARD,
                        "kb_tamper_guard",
                        "知识库篡改写入已拒绝",
                        str(dg.get("detail", "")),
                        Severity.CRITICAL,
                        dict(dg),
                        ("reject_request", "rollback_config"),
                    )
                )
            if dg.get("illegal_read_blocked"):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.DATA_GUARD,
                        "read_guard",
                        "非法读取敏感存储已阻断",
                        str(dg.get("path", "")),
                        Severity.HIGH,
                        dict(dg),
                        ("reject_request",),
                    )
                )

        if sc.last_model_output and find_pii(sc.last_model_output):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.DATA_GUARD,
                    "output_redaction_enforced",
                    "模型输出含敏感信息 — 强制脱敏或拒答",
                    "pii_in_output",
                    Severity.HIGH,
                    {},
                    ("reject_request", "block_tool"),
                )
            )

        if sc.compliance_policy_state.get("dlp_violation_pending"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.DATA_GUARD,
                    "dlp_pending_block",
                    "数据防泄漏策略待处置 — 暂停外发",
                    str(sc.compliance_policy_state.get("detail", "")),
                    Severity.HIGH,
                    dict(sc.compliance_policy_state),
                    ("reject_request", "isolate_session"),
                )
            )

        return s
