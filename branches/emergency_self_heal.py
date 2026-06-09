from __future__ import annotations

from typing import Sequence

from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity


class EmergencySelfHealDetector:
    """
    第十二项：应急自愈联动检测（检测—响应—自愈闭环）。
    校验危急发现后是否落实隔离、限流、熔断、配置回滚、终止恶意行为；
    支持 SLA、仅观测模式缺口、剧本动作账本（action_ledger）与闭环验证（closed_loop_verified）。
    """

    def analyze(
        self,
        ctx: ScanContext,
        prior_findings: Sequence[Finding] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        hp = ctx.healing_pipeline
        prior = list(prior_findings or ())

        if hp.get("security_master_switch_off"):
            findings.append(
                Finding(
                    BranchId.EMERGENCY_SELF_HEAL,
                    "healing_disabled",
                    "应急自愈或主安全开关被关闭",
                    str(hp.get("detail")),
                    Severity.CRITICAL,
                    dict(hp),
                )
            )

        critical = [f for f in prior if f.severity == Severity.CRITICAL]
        if (
            critical
            and not hp.get("isolation_applied")
            and hp.get("require_isolate_on_critical", True)
        ):
            findings.append(
                Finding(
                    BranchId.EMERGENCY_SELF_HEAL,
                    "isolate_gap",
                    "存在危急级发现但未记录隔离动作",
                    f"count_critical={len(critical)}",
                    Severity.HIGH,
                    {"finding_categories": [f.category for f in critical]},
                )
            )

        if hp.get("rate_limit_failed"):
            findings.append(
                Finding(
                    BranchId.EMERGENCY_SELF_HEAL,
                    "rate_limit_gap",
                    "限流未生效或执行失败",
                    str(hp.get("detail")),
                    Severity.MEDIUM,
                    dict(hp),
                )
            )

        if hp.get("circuit_breaker_open_required") and not hp.get("circuit_breaker_open"):
            findings.append(
                Finding(
                    BranchId.EMERGENCY_SELF_HEAL,
                    "breaker_gap",
                    "应熔断但未打开断路器",
                    str(hp.get("service")),
                    Severity.HIGH,
                    dict(hp),
                )
            )

        if hp.get("rollback_required") and not hp.get("rollback_done"):
            findings.append(
                Finding(
                    BranchId.EMERGENCY_SELF_HEAL,
                    "rollback_gap",
                    "配置/策略回滚未完成",
                    str(hp.get("target")),
                    Severity.HIGH,
                    dict(hp),
                )
            )

        if hp.get("malicious_behavior_active") and not hp.get("termination_done"):
            findings.append(
                Finding(
                    BranchId.EMERGENCY_SELF_HEAL,
                    "terminate_gap",
                    "恶意行为未终止或进程仍在运行",
                    str(hp.get("pid_or_task")),
                    Severity.CRITICAL,
                    dict(hp),
                )
            )

        if hp.get("playbook_timeout"):
            findings.append(
                Finding(
                    BranchId.EMERGENCY_SELF_HEAL,
                    "playbook_timeout",
                    "应急剧本执行超时",
                    str(hp.get("playbook")),
                    Severity.MEDIUM,
                    dict(hp),
                )
            )

        sla = hp.get("detection_to_response_ms")
        limit = float(hp.get("response_sla_ms", 5000))
        if isinstance(sla, (int, float)) and sla > limit:
            findings.append(
                Finding(
                    BranchId.EMERGENCY_SELF_HEAL,
                    "response_sla_breach",
                    "检测触发到响应执行的时延超过 SLA（闭环时效风险）",
                    f"{sla}ms > {limit}ms",
                    Severity.MEDIUM,
                    dict(hp),
                )
            )

        sev_prior = [f for f in prior if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        if sev_prior and hp.get("observe_only_mode"):
            findings.append(
                Finding(
                    BranchId.EMERGENCY_SELF_HEAL,
                    "observe_only_no_execute",
                    "存在高危/危急发现但处于仅观测模式，未自动隔离/熔断/终止（闭环缺口）",
                    str(hp.get("detail")),
                    Severity.HIGH,
                    dict(hp),
                )
            )

        ledger = hp.get("action_ledger") or []
        expected_playbook = frozenset(
            str(x) for x in (hp.get("required_playbook_actions") or ()) if x
        )
        if critical and expected_playbook and ledger:
            done = {
                str(x.get("action"))
                for x in ledger
                if isinstance(x, dict) and x.get("status") == "ok"
            }
            missing = sorted(expected_playbook - done)
            if missing:
                findings.append(
                    Finding(
                        BranchId.EMERGENCY_SELF_HEAL,
                        "playbook_incomplete",
                        "应急自愈剧本要求的动作未全部成功执行",
                        ", ".join(missing),
                        Severity.HIGH,
                        {"missing": missing},
                    )
                )

        if critical and hp.get("closed_loop_verified"):
            findings.append(
                Finding(
                    BranchId.EMERGENCY_SELF_HEAL,
                    "detection_response_heal_closed_loop",
                    "检测—响应—自愈闭环已验证（危急场景处置与审计一致）",
                    str(hp.get("closure_summary", "ok")),
                    Severity.INFO,
                    dict(hp),
                )
            )

        return findings
