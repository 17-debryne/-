from __future__ import annotations

from typing import Any, Mapping, Pattern, Sequence
from urllib.parse import urlparse

from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity
from mcp_agent_safe_protecter.shared.escape_patterns import (
    CONSTRAINT_BYPASS_PATTERNS,
    HIGH_PRIV_CMD_PATTERNS,
    JAILBREAK_PATTERNS,
    ROLE_ESCAPE_PATTERNS,
    SECURITY_POLICY_TAMPER_PATTERNS,
    compile_group,
)

# 工具名子串：疑似修改自身安全策略 / 关闭检测能力
_POLICY_SELF_MODIFY_TOOLS: frozenset[str] = frozenset(
    {
        "update_security_policy",
        "patch_guardrails",
        "disable_audit_log",
        "disable_scan_module",
        "set_masp_enabled",
        "override_content_filter",
        "disable_guardrail",
        "clear_safety_rules",
    }
)


class EscapeAbuseDetector:
    """
    第九项：逃逸越权行为专项检测。
    大模型/智能体角色逃逸与越狱、绕过约束、自主未知联网、
    高危系统命令（文本+工具链）、违规修改自身安全策略、关闭安全检测开关；
    支持结构化信号（escape_abuse）与工具参数判别（policy/detect 开关）。
    """

    def __init__(
        self,
        *,
        known_network_allowlist: frozenset[str] | None = None,
    ) -> None:
        self._role = compile_group(ROLE_ESCAPE_PATTERNS)
        self._jail = compile_group(JAILBREAK_PATTERNS)
        self._bypass = compile_group(CONSTRAINT_BYPASS_PATTERNS)
        self._policy_tamper = compile_group(SECURITY_POLICY_TAMPER_PATTERNS)
        self._priv_cmd = compile_group(HIGH_PRIV_CMD_PATTERNS)
        self._net_allow = known_network_allowlist or frozenset()

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        text = " ".join(x for x in (ctx.last_user_prompt, ctx.last_model_output) if x)
        sig = ctx.escape_abuse

        if sig.get("role_escape_suspected") or self._any_match(self._role, text):
            findings.append(
                Finding(
                    BranchId.ESCAPE_ABUSE,
                    "role_escape",
                    "大模型/智能体角色逃逸可疑",
                    sig.get("detail") or "文本或信号命中角色逃逸模式",
                    Severity.CRITICAL,
                    dict(sig),
                )
            )

        if sig.get("jailbreak_suspected") or self._any_match(self._jail, text):
            findings.append(
                Finding(
                    BranchId.ESCAPE_ABUSE,
                    "jailbreak",
                    "指令越狱可疑",
                    sig.get("detail") or "命中越狱相关表述",
                    Severity.CRITICAL,
                    dict(sig),
                )
            )

        if sig.get("constraint_bypass") or self._any_match(self._bypass, text):
            findings.append(
                Finding(
                    BranchId.ESCAPE_ABUSE,
                    "constraint_bypass",
                    "绕过安全约束",
                    sig.get("detail") or "命中绕过过滤器/策略模式",
                    Severity.HIGH,
                    dict(sig),
                )
            )

        findings.extend(self._unknown_autonomous_network(ctx))
        findings.extend(self._structured_unknown_hosts(sig))

        if sig.get("llm_role_boundary_violation"):
            findings.append(
                Finding(
                    BranchId.ESCAPE_ABUSE,
                    "llm_role_boundary_violation",
                    "大模型角色边界被破坏（采集器标记）",
                    str(sig.get("detail")),
                    Severity.CRITICAL,
                    dict(sig),
                )
            )

        if sig.get("high_priv_command") or self._any_match(self._priv_cmd, text):
            findings.append(
                Finding(
                    BranchId.ESCAPE_ABUSE,
                    "high_privilege_command",
                    "私自执行高危系统命令",
                    sig.get("detail") or "输出或信号含高危命令模式",
                    Severity.CRITICAL,
                    dict(sig),
                )
            )
        findings.extend(self._tool_high_priv(ctx.tool_calls))
        findings.extend(self._tool_policy_tamper(ctx.tool_calls))

        if sig.get("security_policy_self_modify"):
            findings.append(
                Finding(
                    BranchId.ESCAPE_ABUSE,
                    "security_policy_self_modify",
                    "违规修改自身安全策略",
                    str(sig.get("detail")),
                    Severity.CRITICAL,
                    dict(sig),
                )
            )

        if sig.get("security_detection_disabled") or sig.get(
            "security_master_switch_off_attempt"
        ):
            findings.append(
                Finding(
                    BranchId.ESCAPE_ABUSE,
                    "security_detection_disabled",
                    "关闭或试图关闭安全检测开关",
                    sig.get("detail") or "结构化信号：安全检测被关闭或请求关闭",
                    Severity.CRITICAL,
                    dict(sig),
                )
            )
        elif self._any_match(self._policy_tamper, text):
            findings.append(
                Finding(
                    BranchId.ESCAPE_ABUSE,
                    "security_detection_disabled",
                    "关闭或试图关闭安全检测（文本模式命中）",
                    sig.get("detail") or "文本表明检测/审计被关闭",
                    Severity.CRITICAL,
                    dict(sig),
                )
            )

        return findings

    @staticmethod
    def _any_match(patterns: list[Pattern[str]], text: str) -> bool:
        if not text:
            return False
        return any(p.search(text) for p in patterns)

    def _unknown_autonomous_network(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        sig = ctx.escape_abuse
        if sig.get("autonomous_unknown_network"):
            out.append(
                Finding(
                    BranchId.ESCAPE_ABUSE,
                    "autonomous_unknown_network",
                    "智能体自主发起未知联网",
                    str(sig.get("dest")),
                    Severity.HIGH,
                    dict(sig),
                )
            )
            return out
        for r in ctx.raw_http_requests:
            if not r.get("agent_initiated", True):
                continue
            url = str(r.get("url") or "")
            host = ""
            try:
                host = (urlparse(url).hostname or "").lower()
            except ValueError:
                pass
            if host and self._net_allow and host not in self._net_allow:
                if not any(host.endswith(s) for s in (".internal", ".local")):
                    out.append(
                        Finding(
                            BranchId.ESCAPE_ABUSE,
                            "autonomous_unknown_network",
                            "自主外联命中非白名单主机",
                            url,
                            Severity.HIGH,
                            {"host": host},
                        )
                    )
        return out

    def _structured_unknown_hosts(self, sig: Mapping[str, Any]) -> list[Finding]:
        """采集器上报的未知外联目标列表（自主联网）。"""
        out: list[Finding] = []
        for item in sig.get("unknown_outbound_hosts") or ():
            if isinstance(item, dict):
                dest = str(item.get("host") or item.get("url") or "")
                detail = str(item.get("detail") or "未登记外联")
            else:
                dest = str(item)
                detail = "未登记外联"
            if not dest:
                continue
            out.append(
                Finding(
                    BranchId.ESCAPE_ABUSE,
                    "autonomous_unknown_network",
                    "自主发起未知联网（采集器枚举）",
                    detail,
                    Severity.HIGH,
                    {"dest": dest, **(item if isinstance(item, dict) else {})},
                )
            )
        return out

    def _tool_high_priv(self, calls: Sequence[Mapping[str, Any]]) -> list[Finding]:
        out: list[Finding] = []
        risky = frozenset(
            {"run_shell", "exec", "sudo", "powershell", "cmd", "chmod", "mount"}
        )
        for c in calls:
            name = str(c.get("name") or c.get("tool") or "").lower()
            if name in risky or any(k in name for k in ("shell", "exec", "sudo")):
                out.append(
                    Finding(
                        BranchId.ESCAPE_ABUSE,
                        "tool_high_privilege",
                        "工具链路涉及高危系统执行能力",
                        name,
                        Severity.HIGH,
                        dict(c),
                    )
                )
        return out

    def _tool_policy_tamper(self, calls: Sequence[Mapping[str, Any]]) -> list[Finding]:
        out: list[Finding] = []
        for c in calls:
            raw = str(c.get("name") or c.get("tool") or "")
            name = raw.lower()
            hit = name in _POLICY_SELF_MODIFY_TOOLS or any(
                t in name for t in ("guardrail_off", "disable_scan", "policy_patch")
            )
            args = c.get("arguments")
            ad: dict[str, Any] = args if isinstance(args, dict) else {}
            sec_false = (
                ad.get("security_enabled") is False
                or ad.get("detection_enabled") is False
                or (ad.get("enabled") is False and "guardrail" in name)
            )
            if hit or sec_false:
                out.append(
                    Finding(
                        BranchId.ESCAPE_ABUSE,
                        "tool_security_policy_tamper",
                        "通过工具调用违规修改安全策略或关闭检测相关开关",
                        raw or name,
                        Severity.CRITICAL,
                        dict(c),
                    )
                )
        return out
