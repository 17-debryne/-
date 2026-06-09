from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Mapping, Sequence

from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity

if TYPE_CHECKING:
    from mcp_agent_safe_protecter.branches.emergency_self_heal import (
        EmergencySelfHealDetector,
    )


class HealingActionType(str, Enum):
    ISOLATE = "isolate"
    RATE_LIMIT = "rate_limit"
    CIRCUIT_BREAK = "circuit_break"
    ROLLBACK_CONFIG = "rollback_config"
    TERMINATE = "terminate"
    ENABLE_SAFE_MODE = "enable_safe_mode"


@dataclass(slots=True)
class HealingAction:
    type: HealingActionType
    target: str = ""
    params: Mapping[str, Any] = field(default_factory=dict)
    reason: str = ""
    related_finding: str = ""


@dataclass(slots=True)
class HealingResult:
    action: HealingAction
    ok: bool
    message: str = ""


Executor = Callable[[HealingAction], HealingResult]


class HealingOrchestrator:
    """
    检测-响应-自愈：根据 Finding 生成动作计划，并可挂载真实执行器（隔离/限流等）。
    默认执行器为占位，仅记录成功，便于接入 K8s、服务网格、WAF、进程管理等。
    """

    def __init__(
        self,
        *,
        executor: Executor | None = None,
        isolate_on: frozenset[BranchId] | None = None,
    ) -> None:
        self._executor = executor or self._noop_executor
        self._isolate_on = isolate_on or frozenset(
            {
                BranchId.ESCAPE_ABUSE,
                BranchId.CHAIN_LINKAGE,
                BranchId.GLOBAL_THREAT,
                BranchId.ACCESS_CONTROL,
            }
        )

    @staticmethod
    def _noop_executor(action: HealingAction) -> HealingResult:
        return HealingResult(action, True, "noop_executor")

    def plan(self, findings: Sequence[Finding]) -> list[HealingAction]:
        actions: list[HealingAction] = []
        sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}
        sorted_f = sorted(findings, key=lambda x: sev_order.get(x.severity, 9))

        for f in sorted_f:
            if f.severity not in (Severity.CRITICAL, Severity.HIGH):
                continue
            rid = f"{f.branch.value}:{f.category}"
            if f.branch in self._isolate_on and f.severity == Severity.CRITICAL:
                actions.append(
                    HealingAction(
                        type=HealingActionType.ISOLATE,
                        target="agent_runtime",
                        params={"scope": "network_and_tools"},
                        reason=f.title,
                        related_finding=rid,
                    )
                )
            if f.category in {
                "autonomous_unknown_network",
                "mitm_tls_pin",
                "illegal_callback",
                "api_success_rate_low",
            }:
                actions.append(
                    HealingAction(
                        type=HealingActionType.RATE_LIMIT,
                        target="egress_and_api",
                        params={"rps": 5},
                        reason=f.title,
                        related_finding=rid,
                    )
                )
            if f.branch == BranchId.BUSINESS_HEALTH and f.category == "metric_threshold":
                actions.append(
                    HealingAction(
                        type=HealingActionType.CIRCUIT_BREAK,
                        target="inference_service",
                        params={},
                        reason=f.title,
                        related_finding=rid,
                    )
                )
            if f.branch in (BranchId.COMPLIANCE_POLICY, BranchId.ASSET_INTEGRITY):
                actions.append(
                    HealingAction(
                        type=HealingActionType.ROLLBACK_CONFIG,
                        target="policy_bundle",
                        params={},
                        reason=f.title,
                        related_finding=rid,
                    )
                )
            if f.branch == BranchId.ESCAPE_ABUSE and f.severity == Severity.CRITICAL:
                actions.append(
                    HealingAction(
                        type=HealingActionType.TERMINATE,
                        target="malicious_tool_session",
                        params={},
                        reason=f.title,
                        related_finding=rid,
                    )
                )

        if any(f.severity == Severity.CRITICAL for f in findings):
            actions.append(
                HealingAction(
                    type=HealingActionType.ENABLE_SAFE_MODE,
                    target="agent",
                    params={"disable_tools": True},
                    reason="critical_incident",
                    related_finding="aggregate",
                )
            )

        return self._dedupe(actions)

    @staticmethod
    def _dedupe(actions: list[HealingAction]) -> list[HealingAction]:
        seen: set[tuple[str, str, str]] = set()
        out: list[HealingAction] = []
        for a in actions:
            key = (a.type.value, a.target, a.reason)
            if key in seen:
                continue
            seen.add(key)
            out.append(a)
        return out

    def apply(self, actions: Sequence[HealingAction]) -> list[HealingResult]:
        return [self._executor(a) for a in actions]

    def run_closed_loop(
        self,
        ctx: ScanContext,
        findings: Sequence[Finding],
        self_heal_detector: EmergencySelfHealDetector,
    ) -> tuple[list[HealingAction], list[HealingResult], list[Finding]]:
        """
        先规划并执行自愈，再把执行摘要写入 ctx.healing_pipeline 供 EmergencySelfHealDetector 复查。
        """
        plan = self.plan(findings)
        results = self.apply(plan)
        paired = list(zip(plan, results))
        summary = {
            "isolation_applied": any(
                a.type == HealingActionType.ISOLATE and r.ok for a, r in paired
            ),
            "rate_limit_applied": any(
                a.type == HealingActionType.RATE_LIMIT and r.ok for a, r in paired
            ),
            "circuit_breaker_open": any(
                a.type == HealingActionType.CIRCUIT_BREAK and r.ok for a, r in paired
            ),
            "rollback_done": any(
                a.type == HealingActionType.ROLLBACK_CONFIG and r.ok for a, r in paired
            ),
            "termination_done": any(
                a.type == HealingActionType.TERMINATE and r.ok for a, r in paired
            ),
            "last_actions": [a.type.value for a in plan],
        }
        ctx.healing_pipeline = {**dict(ctx.healing_pipeline), **summary}
        extra = self_heal_detector.analyze(ctx, prior_findings=findings)
        return plan, results, extra
