from __future__ import annotations

from mcp_agent_safe_protecter.core.types import Severity
from mcp_agent_safe_protecter.protection.context import ProtectionEvaluationContext
from mcp_agent_safe_protecter.protection.types import ProtectionBranchId, ProtectionSignal


class AgentSelfProtection:
    """
    分支③ 智能体本体自防护。
    防注入、防结束、防劫持；配置/策略/程序防篡改、防删除；安全模块防关闭、防绕过、防禁用；
    自检异常时自我锁定、隔离自保。
    """

    def analyze(self, ctx: ProtectionEvaluationContext) -> list[ProtectionSignal]:
        s: list[ProtectionSignal] = []
        sc = ctx.scan.self_check

        if sc.get("anti_injection_armed") is False:
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.AGENT_SELF,
                    "anti_injection_disabled",
                    "本体防注入能力未启用 — 建议强制开启",
                    str(sc.get("detail", "")),
                    Severity.CRITICAL,
                    dict(sc),
                    ("rollback_config", "alert_soc"),
                )
            )

        if sc.get("process_termination_attempt"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.AGENT_SELF,
                    "anti_kill_guard",
                    "检测到进程被结束尝试 — 触发守护与拉起策略",
                    str(sc.get("detail", "")),
                    Severity.HIGH,
                    dict(sc),
                    ("isolate_session", "alert_soc"),
                )
            )

        if sc.get("api_hijack_attempt") or sc.get("suspected_api_hooks"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.AGENT_SELF,
                    "anti_hijack_guard",
                    "API/调用链劫持尝试 — 锁定自身句柄与校验映像",
                    str(sc.get("hook_detail", "")),
                    Severity.CRITICAL,
                    dict(sc),
                    ("isolate_session", "block_tool"),
                )
            )

        if sc.get("config_tamper_blocked"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.AGENT_SELF,
                    "config_tamper_block",
                    "配置篡改已被自防护拦截",
                    str(sc.get("path", "")),
                    Severity.HIGH,
                    dict(sc),
                    ("rollback_config",),
                )
            )

        if sc.get("policy_file_delete_attempt"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.AGENT_SELF,
                    "policy_delete_guard",
                    "策略/程序文件删除尝试 — 拒绝并告警",
                    str(sc.get("path", "")),
                    Severity.CRITICAL,
                    dict(sc),
                    ("reject_request", "alert_soc"),
                )
            )

        if sc.get("security_module_disable_attempt"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.AGENT_SELF,
                    "security_module_guard",
                    "安全模块关闭/绕过/禁用尝试 — 维持模块强制启用",
                    str(sc.get("detail", "")),
                    Severity.CRITICAL,
                    dict(sc),
                    ("reject_request", "rollback_config", "alert_soc"),
                )
            )

        if sc.get("self_lockdown_active"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.AGENT_SELF,
                    "self_lockdown",
                    "自检异常触发自锁与隔离自保（已激活）",
                    str(sc.get("reason", "")),
                    Severity.HIGH,
                    dict(sc),
                    ("isolate_session",),
                )
            )
        elif sc.get("require_self_lockdown"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.AGENT_SELF,
                    "self_lockdown_recommend",
                    "自检异常 — 建议立即自我锁定与隔离",
                    str(sc.get("reason", "")),
                    Severity.CRITICAL,
                    dict(sc),
                    ("isolate_session", "alert_soc"),
                )
            )

        return s
