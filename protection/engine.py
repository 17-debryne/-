from __future__ import annotations

from dataclasses import dataclass, field

from mcp_agent_safe_protecter.protection.branches import (
    AgentSelfProtection,
    BusinessBehaviorProtection,
    CounterstrikeProtection,
    DataGuardProtection,
    ExternalIntrusionProtection,
    PrivilegeBoundaryProtection,
    SystemComponentProtection,
)
from mcp_agent_safe_protecter.protection.context import ProtectionEvaluationContext
from mcp_agent_safe_protecter.protection.types import ProtectionBranchId, ProtectionSignal


@dataclass
class ProtectionEngine:
    """
    安全防护总编排：七大分支并行评估，产出可执行的防护信号。
    """

    _runners: list[tuple[ProtectionBranchId, object]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self._runners:
            self._runners = [
                (ProtectionBranchId.SYSTEM_COMPONENT, SystemComponentProtection()),
                (ProtectionBranchId.BUSINESS_BEHAVIOR, BusinessBehaviorProtection()),
                (ProtectionBranchId.AGENT_SELF, AgentSelfProtection()),
                (ProtectionBranchId.EXTERNAL_INTRUSION, ExternalIntrusionProtection()),
                (ProtectionBranchId.PRIVILEGE_BOUNDARY, PrivilegeBoundaryProtection()),
                (ProtectionBranchId.DATA_GUARD, DataGuardProtection()),
                (ProtectionBranchId.COUNTERSTRIKE, CounterstrikeProtection()),
            ]

    def run(
        self,
        ctx: ProtectionEvaluationContext,
        *,
        enabled_branches: frozenset[ProtectionBranchId] | None = None,
    ) -> list[ProtectionSignal]:
        out: list[ProtectionSignal] = []
        for bid, runner in self._runners:
            if enabled_branches is not None and bid not in enabled_branches:
                continue
            analyze = getattr(runner, "analyze", None)
            if callable(analyze):
                out.extend(analyze(ctx))
        return out
