from __future__ import annotations

from enum import Enum, auto

from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity


class SelfCheckMode(Enum):
    PERIODIC = auto()
    TRIGGERED = auto()


class SelfTrustDetector:
    """
    分支四：智能体自身可信自检。
    权限合规、进程注入/钩子、守护进程、日志被清空、启动项、依赖组件可信；
    支持 periodic / triggered 模式标记。
    """

    def analyze(
        self, ctx: ScanContext, *, mode: SelfCheckMode = SelfCheckMode.TRIGGERED
    ) -> list[Finding]:
        findings: list[Finding] = []
        sc = ctx.self_check
        evidence_mode = {"self_check_mode": mode.name}

        if mode == SelfCheckMode.PERIODIC:
            findings.append(
                Finding(
                    BranchId.SELF_TRUST,
                    "periodic_self_check",
                    "周期性自检已执行",
                    "智能体自身可信自检（周期任务）",
                    Severity.INFO,
                    evidence_mode,
                )
            )
        else:
            findings.append(
                Finding(
                    BranchId.SELF_TRUST,
                    "triggered_self_check",
                    "触发式自检已执行",
                    "智能体自身可信自检（事件触发）",
                    Severity.INFO,
                    evidence_mode,
                )
            )

        perms = sc.get("effective_permissions") or []
        allowed = set(sc.get("allowed_permissions") or [])
        if allowed:
            for p in perms:
                if p not in allowed:
                    findings.append(
                        Finding(
                            BranchId.SELF_TRUST,
                            "permission_self_compliance",
                            "自身权限超出合规集合",
                            str(p),
                            Severity.HIGH,
                            {**evidence_mode, "permission": p},
                        )
                    )

        if sc.get("suspected_process_injection"):
            findings.append(
                Finding(
                    BranchId.SELF_TRUST,
                    "process_injection",
                    "检测到疑似进程注入",
                    str(sc.get("injection_detail")),
                    Severity.CRITICAL,
                    evidence_mode,
                )
            )
        if sc.get("suspected_api_hooks"):
            findings.append(
                Finding(
                    BranchId.SELF_TRUST,
                    "api_hook",
                    "检测到疑似 API/函数钩子",
                    str(sc.get("hook_detail")),
                    Severity.HIGH,
                    evidence_mode,
                )
            )

        daemons = sc.get("daemon_heartbeats") or {}
        for name, last_ok in daemons.items():
            if not last_ok:
                findings.append(
                    Finding(
                        BranchId.SELF_TRUST,
                        "daemon_unhealthy",
                        "守护进程状态异常",
                        str(name),
                        Severity.HIGH,
                        {**evidence_mode, "daemon": name},
                    )
                )

        log_meta = sc.get("audit_log_integrity") or {}
        if log_meta.get("was_truncated_or_cleared"):
            findings.append(
                Finding(
                    BranchId.SELF_TRUST,
                    "log_tamper",
                    "自身审计日志疑似被清空或截断",
                    str(log_meta.get("path")),
                    Severity.CRITICAL,
                    {**evidence_mode, **log_meta},
                )
            )

        startup = sc.get("startup_items") or []
        baseline_startup = set(sc.get("baseline_startup_items") or [])
        if baseline_startup:
            for item in startup:
                if item not in baseline_startup:
                    findings.append(
                        Finding(
                            BranchId.SELF_TRUST,
                            "startup_tamper",
                            "启动项相对基线发生变化",
                            str(item),
                            Severity.HIGH,
                            {**evidence_mode, "item": item},
                        )
                    )

        deps = sc.get("dependency_attestations") or {}
        for comp, trusted in deps.items():
            if not trusted:
                findings.append(
                    Finding(
                        BranchId.SELF_TRUST,
                        "dependency_untrusted",
                        "依赖组件未通过可信校验",
                        str(comp),
                        Severity.MEDIUM,
                        {**evidence_mode, "component": comp},
                    )
                )

        return findings
