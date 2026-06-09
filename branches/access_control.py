from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity

_WEAK_PASSWORD = re.compile(r"^(.{0,7}|[^A-Z]*|[^a-z]*|[^0-9]*|[^\W]*)$")


class AccessControlDetector:
    """
    分支五：权限与访问控制检测。
    账号/角色溢出、后台越权、未授权接口、弱口令/匿名、跨租户；
    适配智能体角色与多工具调用的权限边界。
    """

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        principal = ctx.principal
        policy = ctx.rbac_policy
        action = ctx.attempted_action

        role_caps: set[str] = set(
            (policy.get("role_capabilities") or {}).get(principal.get("role"), [])
        )
        required = set(action.get("required_capabilities") or [])
        if required and not required.issubset(role_caps):
            findings.append(
                Finding(
                    BranchId.ACCESS_CONTROL,
                    "role_capability_overflow",
                    "智能体角色权限不足以执行该动作（或策略配置异常）",
                    str(action),
                    Severity.HIGH,
                    {"missing": sorted(required - role_caps)},
                )
            )

        if action.get("target") == "admin_console" and "admin.access" not in role_caps:
            findings.append(
                Finding(
                    BranchId.ACCESS_CONTROL,
                    "backend_elevation",
                    "越权访问后台/管理面",
                    str(action),
                    Severity.CRITICAL,
                    {},
                )
            )

        if action.get("api") and not action.get("authorized", True):
            findings.append(
                Finding(
                    BranchId.ACCESS_CONTROL,
                    "unauthorized_api",
                    "未授权接口调用",
                    str(action.get("api")),
                    Severity.HIGH,
                    dict(action),
                )
            )

        auth = principal.get("auth") or {}
        if auth.get("anonymous"):
            findings.append(
                Finding(
                    BranchId.ACCESS_CONTROL,
                    "anonymous_access",
                    "匿名访问敏感能力",
                    str(action.get("name")),
                    Severity.HIGH,
                    {},
                )
            )
        pwd = auth.get("password")
        if isinstance(pwd, str) and _WEAK_PASSWORD.match(pwd):
            findings.append(
                Finding(
                    BranchId.ACCESS_CONTROL,
                    "weak_password",
                    "弱口令策略未满足",
                    principal.get("user_id", ""),
                    Severity.MEDIUM,
                    {},
                )
            )

        roles = principal.get("roles")
        if isinstance(roles, list):
            max_roles = policy.get("max_roles")
            if max_roles is not None and len(roles) > int(max_roles):
                findings.append(
                    Finding(
                        BranchId.ACCESS_CONTROL,
                        "role_count_overflow",
                        "智能体账号角色数量溢出（相对策略上限）",
                        str(len(roles)),
                        Severity.HIGH,
                        {"roles": roles, "max_roles": max_roles},
                    )
                )

        tenant_actor = str(principal.get("tenant_id") or ctx.tenant_id)
        resource_tenant = str(action.get("resource_tenant_id") or tenant_actor)
        if resource_tenant and tenant_actor and resource_tenant != tenant_actor:
            findings.append(
                Finding(
                    BranchId.ACCESS_CONTROL,
                    "cross_tenant",
                    "非法跨租户资源访问",
                    f"{tenant_actor} -> {resource_tenant}",
                    Severity.CRITICAL,
                    {},
                )
            )

        findings.extend(self._tool_boundary(ctx.tool_calls, policy))

        return findings

    def _tool_boundary(
        self, calls: Sequence[Mapping[str, Any]], policy: Mapping[str, Any]
    ) -> list[Finding]:
        allowed_tools = set(policy.get("allowed_tools_for_role") or [])
        if not allowed_tools:
            return []
        out: list[Finding] = []
        for c in calls:
            name = str(c.get("name") or c.get("tool") or "")
            if name and name not in allowed_tools:
                out.append(
                    Finding(
                        BranchId.ACCESS_CONTROL,
                        "tool_permission_boundary",
                        "工具调用超出角色允许集合",
                        name,
                        Severity.HIGH,
                        {"tool": name},
                    )
                )
        return out
