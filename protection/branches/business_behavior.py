from __future__ import annotations

from typing import Any, Mapping

from mcp_agent_safe_protecter.core.types import Severity
from mcp_agent_safe_protecter.protection.context import ProtectionEvaluationContext
from mcp_agent_safe_protecter.protection.types import ProtectionBranchId, ProtectionSignal


class BusinessBehaviorProtection:
    """
    分支② 业务行为风险防护。
    违规指令、越权操作、异常任务流、高危行为拦截、不合规工具调用、敏感操作前置阻断、行为基线实时拦截（事前）。
    """

    def analyze(self, ctx: ProtectionEvaluationContext) -> list[ProtectionSignal]:
        s: list[ProtectionSignal] = []
        sc = ctx.scan
        sig = sc.self_check.get("business_behavior_guard") or {}
        if isinstance(sig, dict):
            if sig.get("illegal_instruction_blocked"):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.BUSINESS_BEHAVIOR,
                        "instruction_preflight_deny",
                        "违规指令已在执行前阻断",
                        str(sig.get("detail", "")),
                        Severity.HIGH,
                        dict(sig),
                        ("reject_request",),
                    )
                )
            if sig.get("sensitive_op_requires_approval") and not sig.get("approval_ok"):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.BUSINESS_BEHAVIOR,
                        "sensitive_pre_block",
                        "敏感操作缺少事前审批 — 默认拦截",
                        str(sig.get("op", "")),
                        Severity.HIGH,
                        dict(sig),
                        ("reject_request", "block_tool"),
                    )
                )

        action = sc.attempted_action
        if action.get("requires_pre_approval") and not action.get("pre_approved"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.BUSINESS_BEHAVIOR,
                    "pre_approval_gate",
                    "动作需要事前审批 — 防护门尚未放行",
                    str(action.get("name", "")),
                    Severity.HIGH,
                    dict(action),
                    ("reject_request",),
                )
            )

        for task in sc.task_states:
            if str(task.get("state")) in {"illegal_transition", "policy_violation"}:
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.BUSINESS_BEHAVIOR,
                        "task_flow_guard",
                        "异常任务流转 — 拦截后续 hop",
                        str(task),
                        Severity.MEDIUM,
                        dict(task),
                        ("reject_request", "block_tool"),
                    )
                )

        policy = sc.rbac_policy
        allowed_tools = set(policy.get("allowed_tools_for_role") or [])
        if allowed_tools:
            for c in sc.tool_calls:
                name = str(c.get("name") or c.get("tool") or "")
                if name and name not in allowed_tools:
                    s.append(
                        ProtectionSignal(
                            ProtectionBranchId.BUSINESS_BEHAVIOR,
                            "tool_compliance_block",
                            "不合规工具调用 — 事前拦截",
                            name,
                            Severity.HIGH,
                            dict(c),
                            ("block_tool", "reject_request"),
                        )
                    )

        baseline = sc.session_info.get("behavior_baseline_violation")
        if baseline:
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.BUSINESS_BEHAVIOR,
                    "baseline_realtime_block",
                    "偏离行为基线 — 实时风险拦截",
                    str(baseline),
                    Severity.HIGH,
                    {"baseline": baseline},
                    ("reject_request", "isolate_session"),
                )
            )

        if sc.session_info.get("high_risk_behavior_flag"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.BUSINESS_BEHAVIOR,
                    "high_risk_intercept",
                    "高危行为标记 — 建议立即熔断相关通路",
                    str(sc.session_info.get("detail", "")),
                    Severity.CRITICAL,
                    dict(sc.session_info),
                    ("block_tool", "isolate_session", "alert_soc"),
                )
            )

        return s
