from __future__ import annotations

import re

from mcp_agent_safe_protecter.core.types import Severity
from mcp_agent_safe_protecter.protection.context import ProtectionEvaluationContext
from mcp_agent_safe_protecter.protection.types import ProtectionBranchId, ProtectionSignal
from mcp_agent_safe_protecter.shared.patterns import (
    PROMPT_INJECTION_PATTERNS,
    compile_patterns,
)


class ExternalIntrusionProtection:
    """
    分支④ 外部入侵与恶意攻击防护。
    网络攻击、端口探测、恶意请求、Prompt 注入、提示词投毒、越狱、指令绕过、非法接入、
    恶意域名、挖矿、远控木马类拦截。
    """

    _inj = compile_patterns(PROMPT_INJECTION_PATTERNS)
    _MINING_HOST = re.compile(
        r"(stratum\+tcp|xmrig|minergate|nicehash|pool\.)", re.I
    )
    _RAT_HINT = re.compile(
        r"(teamviewer\s+silent|anydesk\s+--install|ngrok\.io|reverse\s+shell)", re.I
    )

    def analyze(self, ctx: ProtectionEvaluationContext) -> list[ProtectionSignal]:
        s: list[ProtectionSignal] = []
        sc = ctx.scan
        env = sc.environment_profile

        if env.get("port_scan_detected"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.EXTERNAL_INTRUSION,
                    "port_scan_block",
                    "端口探测行为 — 联动防火墙丢弃来源",
                    str(env.get("src", "")),
                    Severity.HIGH,
                    dict(env),
                    ("reject_request", "alert_soc"),
                )
            )

        if env.get("network_attack_signature"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.EXTERNAL_INTRUSION,
                    "network_attack_block",
                    "网络攻击特征命中 — 阻断会话",
                    str(env.get("signature", "")),
                    Severity.CRITICAL,
                    dict(env),
                    ("isolate_session", "reject_request", "alert_soc"),
                )
            )

        blob = " ".join(x for x in (sc.last_user_prompt, sc.last_model_output) if x)
        if blob and any(p.search(blob) for p in self._inj):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.EXTERNAL_INTRUSION,
                    "prompt_injection_block",
                    "Prompt 注入 / 提示词投毒 — 丢弃本轮并审计",
                    "pattern_hit",
                    Severity.HIGH,
                    {},
                    ("reject_request", "block_tool"),
                )
            )

        ext = sc.self_check.get("external_intrusion") or {}
        if isinstance(ext, dict):
            if ext.get("jailbreak_active_session"):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.EXTERNAL_INTRUSION,
                        "jailbreak_session_block",
                        "越狱攻击会话 — 终止上下文",
                        str(ext.get("detail", "")),
                        Severity.CRITICAL,
                        dict(ext),
                        ("reject_request", "isolate_session"),
                    )
                )
            if ext.get("illegal_access_attempt"):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.EXTERNAL_INTRUSION,
                        "illegal_access_block",
                        "非法访问攻击 — 拒绝并记录来源",
                        str(ext.get("detail", "")),
                        Severity.HIGH,
                        dict(ext),
                        ("reject_request", "revoke_token"),
                    )
                )

        for r in sc.raw_http_requests:
            url = str(r.get("url") or "")
            if self._MINING_HOST.search(url):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.EXTERNAL_INTRUSION,
                        "mining_block",
                        "挖矿类外联 — 阻断出站",
                        url,
                        Severity.CRITICAL,
                        dict(r),
                        ("reject_request", "block_tool", "alert_soc"),
                    )
                )
            if self._RAT_HINT.search(url) or self._RAT_HINT.search(str(r.get("body", ""))):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.EXTERNAL_INTRUSION,
                        "rat_block",
                        "远控木马类载荷特征 — 阻断",
                        url,
                        Severity.CRITICAL,
                        dict(r),
                        ("reject_request", "isolate_session", "alert_soc"),
                    )
                )
            if r.get("malicious_request_score", 0) > float(r.get("threshold", 0.8)):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.EXTERNAL_INTRUSION,
                        "malicious_request_block",
                        "恶意请求评分超阈 — 丢弃",
                        url,
                        Severity.HIGH,
                        dict(r),
                        ("reject_request",),
                    )
                )

        return s
