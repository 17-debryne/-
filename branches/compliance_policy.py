from __future__ import annotations

from typing import Any, Mapping, Sequence

from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity


class CompliancePolicyDetector:
    """
    第十一项：合规策略检测。
    安全策略、风控规则与白名单完整性（哈希/签名）、缺失与版本漂移、
    规则冲突、必备控制被禁用、违规放行高危行为。
    """

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        st = ctx.compliance_policy_state

        for item in st.get("tampered_components") or ():
            nm = str(item.get("name") or item)
            findings.append(
                Finding(
                    BranchId.COMPLIANCE_POLICY,
                    "policy_tampered",
                    "安全策略或风控组件疑似被篡改（提示：请核对权威源与审计记录）",
                    nm,
                    Severity.CRITICAL,
                    dict(item) if isinstance(item, Mapping) else {"name": item},
                )
            )

        if st.get("hash_mismatch"):
            findings.append(
                Finding(
                    BranchId.COMPLIANCE_POLICY,
                    "policy_hash_mismatch",
                    "策略/规则文件哈希与可信基线不一致（提示：可能被篡改）",
                    str(st.get("path")),
                    Severity.CRITICAL,
                    dict(st),
                )
            )

        if st.get("signed_policy_invalid"):
            findings.append(
                Finding(
                    BranchId.COMPLIANCE_POLICY,
                    "policy_signature_invalid",
                    "策略/白名单数字签名无效（提示：可能被篡改或替换）",
                    str(st.get("signed_path")),
                    Severity.CRITICAL,
                    dict(st),
                )
            )

        for missing in st.get("missing_policies") or ():
            findings.append(
                Finding(
                    BranchId.COMPLIANCE_POLICY,
                    "policy_missing",
                    "缺失必备安全或风控策略",
                    str(missing),
                    Severity.HIGH,
                    {"policy": missing},
                )
            )

        for conflict in st.get("rule_conflicts") or ():
            findings.append(
                Finding(
                    BranchId.COMPLIANCE_POLICY,
                    "rule_conflict",
                    "规则之间存在冲突",
                    str(conflict.get("description") or conflict),
                    Severity.MEDIUM,
                    dict(conflict) if isinstance(conflict, Mapping) else {},
                )
            )

        if st.get("high_risk_bypass"):
            findings.append(
                Finding(
                    BranchId.COMPLIANCE_POLICY,
                    "high_risk_allow",
                    "违规放行高危行为（绕过风控/白名单失效）",
                    str(st.get("bypass_detail")),
                    Severity.CRITICAL,
                    dict(st),
                )
            )

        for dc in st.get("disabled_controls") or ():
            findings.append(
                Finding(
                    BranchId.COMPLIANCE_POLICY,
                    "mandatory_control_disabled",
                    "必备风控/合规控制被关闭或非预期禁用（提示：核对变更授权）",
                    str(dc.get("name") if isinstance(dc, Mapping) else dc),
                    Severity.HIGH,
                    dict(dc) if isinstance(dc, Mapping) else {"control": dc},
                )
            )

        if st.get("policy_revision_stale"):
            findings.append(
                Finding(
                    BranchId.COMPLIANCE_POLICY,
                    "policy_revision_stale",
                    "策略版本落后于强制基线（提示：可能存在缺失或未同步）",
                    str(st.get("revision_detail")),
                    Severity.MEDIUM,
                    dict(st),
                )
            )

        findings.extend(self._whitelist_integrity(st.get("whitelists") or ()))

        return findings

    def _whitelist_integrity(self, entries: Sequence[Mapping[str, Any]]) -> list[Finding]:
        out: list[Finding] = []
        for w in entries:
            if w.get("tampered"):
                out.append(
                    Finding(
                        BranchId.COMPLIANCE_POLICY,
                        "whitelist_tampered",
                        "白名单配置疑似被篡改",
                        str(w.get("name")),
                        Severity.HIGH,
                        dict(w),
                    )
                )
        return out
