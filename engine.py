from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from mcp_agent_safe_protecter.branches.access_control import AccessControlDetector
from mcp_agent_safe_protecter.branches.asset_integrity import AssetIntegrityDetector
from mcp_agent_safe_protecter.branches.behavior_audit import BehaviorAuditDetector
from mcp_agent_safe_protecter.branches.business_health import BusinessHealthDetector
from mcp_agent_safe_protecter.branches.chain_linkage import ChainLinkageDetector
from mcp_agent_safe_protecter.branches.compliance_policy import CompliancePolicyDetector
from mcp_agent_safe_protecter.branches.data_security import DataSecurityDetector
from mcp_agent_safe_protecter.branches.emergency_self_heal import EmergencySelfHealDetector
from mcp_agent_safe_protecter.branches.environment_trust import EnvironmentTrustDetector
from mcp_agent_safe_protecter.branches.escape_abuse import EscapeAbuseDetector
from mcp_agent_safe_protecter.branches.global_threat import GlobalThreatDetector
from mcp_agent_safe_protecter.branches.self_trust import SelfCheckMode, SelfTrustDetector
from mcp_agent_safe_protecter.branches.traceability import TraceabilityDetector
from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext


@dataclass
class SecurityDetectionEngine:
    """
    安全检测总编排：按分支并行收集 Finding，可按需裁剪分支。
    """

    global_threat: GlobalThreatDetector = field(default_factory=GlobalThreatDetector)
    business_health: BusinessHealthDetector = field(default_factory=BusinessHealthDetector)
    asset_integrity: AssetIntegrityDetector = field(default_factory=AssetIntegrityDetector)
    self_trust: SelfTrustDetector = field(default_factory=SelfTrustDetector)
    access_control: AccessControlDetector = field(default_factory=AccessControlDetector)
    behavior_audit: BehaviorAuditDetector = field(default_factory=BehaviorAuditDetector)
    data_security: DataSecurityDetector = field(default_factory=DataSecurityDetector)
    environment_trust: EnvironmentTrustDetector = field(
        default_factory=EnvironmentTrustDetector
    )
    escape_abuse: EscapeAbuseDetector = field(default_factory=EscapeAbuseDetector)
    chain_linkage: ChainLinkageDetector = field(default_factory=ChainLinkageDetector)
    compliance_policy: CompliancePolicyDetector = field(
        default_factory=CompliancePolicyDetector
    )
    emergency_self_heal: EmergencySelfHealDetector = field(
        default_factory=EmergencySelfHealDetector
    )
    traceability: TraceabilityDetector = field(default_factory=TraceabilityDetector)

    enabled_branches: frozenset[BranchId] | None = None

    def run(
        self,
        ctx: ScanContext,
        *,
        self_check_mode: SelfCheckMode = SelfCheckMode.TRIGGERED,
    ) -> list[Finding]:
        all_findings: list[Finding] = []
        runners: list[tuple[BranchId, list[Finding]]] = [
            (BranchId.GLOBAL_THREAT, self.global_threat.analyze(ctx)),
            (BranchId.BUSINESS_HEALTH, self.business_health.analyze(ctx)),
            (BranchId.ASSET_INTEGRITY, self.asset_integrity.analyze(ctx)),
            (BranchId.SELF_TRUST, self.self_trust.analyze(ctx, mode=self_check_mode)),
            (BranchId.ACCESS_CONTROL, self.access_control.analyze(ctx)),
            (BranchId.BEHAVIOR_AUDIT, self.behavior_audit.analyze(ctx)),
            (BranchId.DATA_SECURITY, self.data_security.analyze(ctx)),
            (BranchId.ENVIRONMENT_TRUST, self.environment_trust.analyze(ctx)),
            (BranchId.ESCAPE_ABUSE, self.escape_abuse.analyze(ctx)),
            (BranchId.CHAIN_LINKAGE, self.chain_linkage.analyze(ctx)),
            (BranchId.COMPLIANCE_POLICY, self.compliance_policy.analyze(ctx)),
            (BranchId.TRACEABILITY, self.traceability.analyze(ctx)),
        ]
        for bid, fs in runners:
            if self.enabled_branches is not None and bid not in self.enabled_branches:
                continue
            all_findings.extend(fs)

        if self.enabled_branches is None or BranchId.EMERGENCY_SELF_HEAL in self.enabled_branches:
            all_findings.extend(
                self.emergency_self_heal.analyze(ctx, prior_findings=all_findings)
            )

        return all_findings

    @staticmethod
    def filter_by_severity(
        findings: Sequence[Finding], min_level: str
    ) -> list[Finding]:
        order = ("info", "low", "medium", "high", "critical")
        idx = order.index(min_level) if min_level in order else 0
        allowed = set(order[idx:])
        return [f for f in findings if f.severity.value in allowed]
