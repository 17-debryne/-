from __future__ import annotations

from mcp_agent_safe_protecter.core.types import Severity
from mcp_agent_safe_protecter.protection.context import ProtectionEvaluationContext
from mcp_agent_safe_protecter.protection.types import ProtectionBranchId, ProtectionSignal


class PrivilegeBoundaryProtection:
    """
    分支⑤ 权限越权防护。
    权限溢出、跨角色越权、非法提权、未授权访问后台、跨租户操作（权限边界管控）。
    """

    def analyze(self, ctx: ProtectionEvaluationContext) -> list[ProtectionSignal]:
        s: list[ProtectionSignal] = []
        sc = ctx.scan
        principal = sc.principal
        policy = sc.rbac_policy
        action = sc.attempted_action

        role_caps: set[str] = set(
            (policy.get("role_capabilities") or {}).get(principal.get("role"), [])
        )
        required = set(action.get("required_capabilities") or [])
        if required and not required.issubset(role_caps):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.PRIVILEGE_BOUNDARY,
                    "capability_overflow_deny",
                    "权限溢出 / 角色能力不足 — 拒绝执行",
                    str(action.get("name", "")),
                    Severity.HIGH,
                    {"missing": sorted(required - role_caps)},
                    ("reject_request", "revoke_token"),
                )
            )

        if action.get("cross_role_forbidden") and action.get("acting_role") != action.get(
            "expected_role"
        ):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.PRIVILEGE_BOUNDARY,
                    "cross_role_deny",
                    "跨角色越权 — 拦截",
                    str(action.get("name", "")),
                    Severity.CRITICAL,
                    dict(action),
                    ("reject_request",),
                )
            )

        if action.get("illegal_elevation_attempt"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.PRIVILEGE_BOUNDARY,
                    "elevation_block",
                    "非法提权尝试 — 拦截",
                    str(action.get("detail", "")),
                    Severity.CRITICAL,
                    dict(action),
                    ("reject_request", "isolate_session", "alert_soc"),
                )
            )

        if action.get("target") == "admin_console" and "admin.access" not in role_caps:
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.PRIVILEGE_BOUNDARY,
                    "admin_access_deny",
                    "未授权访问后台 — 拒绝",
                    str(action),
                    Severity.CRITICAL,
                    {},
                    ("reject_request", "revoke_token"),
                )
            )

        tenant_actor = str(principal.get("tenant_id") or sc.tenant_id)
        resource_tenant = str(action.get("resource_tenant_id") or tenant_actor)
        if resource_tenant and tenant_actor and resource_tenant != tenant_actor:
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.PRIVILEGE_BOUNDARY,
                    "cross_tenant_deny",
                    "跨租户越权 — 强制拒绝",
                    f"{tenant_actor}->{resource_tenant}",
                    Severity.CRITICAL,
                    {},
                    ("reject_request", "revoke_token", "alert_soc"),
                )
            )

        return s
