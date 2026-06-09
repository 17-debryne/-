from __future__ import annotations

import os

from mcp_agent_safe_protecter.core.types import Severity
from mcp_agent_safe_protecter.protection.context import ProtectionEvaluationContext
from mcp_agent_safe_protecter.protection.types import ProtectionBranchId, ProtectionSignal


class CounterstrikeProtection:
    """
    分支⑦ 自卫对抗（合规边界下的防御性自动化）。

    生产实现仅输出**已授权防御剧本**的建议动作（如对恶意来源自动封禁、Sinkhole、
    WAF/ACL 联动），**不**执行对第三方的主动入侵、弱口令爆破等违法行为。
    若 ``protection.counterstrike.authorized_defensive_playbook`` 为真且设置
    ``MASP_DEFENSIVE_PLAYBOOK_OK=1``，方可下发 ``sinkhole`` / ``acl_deny_source`` 等建议。
    """

    def analyze(self, ctx: ProtectionEvaluationContext) -> list[ProtectionSignal]:
        s: list[ProtectionSignal] = []
        sc = ctx.scan
        raw = sc.self_check.get("counterstrike") or sc.healing_pipeline.get("counterstrike") or {}
        if not isinstance(raw, dict):
            return s

        attacker = raw.get("attacker_indicators") or raw.get("malicious_sources") or ()
        if not attacker:
            return s

        env_ok = os.environ.get("MASP_DEFENSIVE_PLAYBOOK_OK", "").strip() in (
            "1",
            "true",
            "yes",
        )
        legal = bool(raw.get("authorized_defensive_playbook")) and bool(
            raw.get("legal_review_ref")
        )

        if raw.get("simulation_only"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.COUNTERSTRIKE,
                    "defensive_playbook_simulation",
                    "防御性自卫剧本（仅模拟，未对任何主机执行主动攻击）",
                    str(raw.get("scenario", "tabletop")),
                    Severity.INFO,
                    dict(raw),
                    ("alert_soc",),
                )
            )
            return s

        if env_ok and legal:
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.COUNTERSTRIKE,
                    "defensive_playbook_staged",
                    "已授权防御剧本：对恶意指标自动封禁/ACL/Sinkhole（由网关执行，非对外入侵）",
                    str(raw.get("playbook", "block_sources")),
                    Severity.MEDIUM,
                    dict(raw),
                    ("sinkhole", "acl_deny_source", "alert_soc"),
                )
            )
        else:
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.COUNTERSTRIKE,
                    "defensive_playbook_requires_authorization",
                    "检测到恶意来源指标，但防御剧本未获环境与法务授权 — 仅告警不落对抗动作",
                    str(list(attacker)[:3]),
                    Severity.HIGH,
                    dict(raw),
                    ("alert_soc",),
                )
            )

        if raw.get("offensive_action_requested"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.COUNTERSTRIKE,
                    "offensive_action_denied_by_policy",
                    "拒绝主动入侵类请求（如对外弱口令/脚本注入）；请改用合法威胁情报与执法流程",
                    str(raw.get("denied_action", "")),
                    Severity.CRITICAL,
                    dict(raw),
                    tuple(),
                )
            )

        return s
