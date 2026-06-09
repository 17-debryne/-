from __future__ import annotations

from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity


class EnvironmentTrustDetector:
    """
    分支八：环境可信检测。
    OS/容器/虚拟机/网络/DNS/代理/宿主篡改、沙箱逃逸、容器权限过大。
    """

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        env = ctx.environment_profile
        baseline = env.get("expected_os_fingerprint")
        actual = env.get("os_fingerprint")
        if baseline and actual and baseline != actual:
            findings.append(
                Finding(
                    BranchId.ENVIRONMENT_TRUST,
                    "os_baseline_drift",
                    "运行环境 OS 指纹与基线不一致",
                    str(actual),
                    Severity.HIGH,
                    {"expected": baseline, "actual": actual},
                )
            )

        if env.get("container_escape_suspected"):
            findings.append(
                Finding(
                    BranchId.ENVIRONMENT_TRUST,
                    "container_escape",
                    "疑似容器逃逸行为",
                    str(env.get("escape_detail")),
                    Severity.CRITICAL,
                    {},
                )
            )

        if env.get("vm_escape_suspected"):
            findings.append(
                Finding(
                    BranchId.ENVIRONMENT_TRUST,
                    "vm_escape",
                    "疑似虚拟机逃逸/异常嵌套",
                    str(env.get("vm_detail")),
                    Severity.CRITICAL,
                    {},
                )
            )

        if env.get("network_anomaly"):
            findings.append(
                Finding(
                    BranchId.ENVIRONMENT_TRUST,
                    "network_anomaly",
                    "网络环境异常（路由/网关/异常网卡）",
                    str(env.get("network_detail")),
                    Severity.MEDIUM,
                    {},
                )
            )

        if env.get("host_tamper"):
            findings.append(
                Finding(
                    BranchId.ENVIRONMENT_TRUST,
                    "host_tamper",
                    "宿主环境篡改",
                    str(env.get("host_detail")),
                    Severity.HIGH,
                    {},
                )
            )

        if env.get("dns_hijack_suspected"):
            findings.append(
                Finding(
                    BranchId.ENVIRONMENT_TRUST,
                    "dns_hijack",
                    "DNS 劫持或解析异常",
                    str(env.get("dns_detail")),
                    Severity.HIGH,
                    {},
                )
            )

        if env.get("proxy_anomaly"):
            findings.append(
                Finding(
                    BranchId.ENVIRONMENT_TRUST,
                    "proxy_anomaly",
                    "代理链异常或未声明的出站代理",
                    str(env.get("proxy_detail")),
                    Severity.MEDIUM,
                    {},
                )
            )

        if env.get("sandbox_escape_suspected"):
            findings.append(
                Finding(
                    BranchId.ENVIRONMENT_TRUST,
                    "sandbox_escape",
                    "沙箱逃逸可疑迹象",
                    str(env.get("sandbox_detail")),
                    Severity.CRITICAL,
                    {},
                )
            )

        caps = env.get("container_capabilities") or []
        dangerous = {"SYS_ADMIN", "DAC_READ_SEARCH", "NET_ADMIN"} & set(caps)
        if dangerous:
            findings.append(
                Finding(
                    BranchId.ENVIRONMENT_TRUST,
                    "excessive_container_priv",
                    "容器权限过大（capabilities）",
                    ", ".join(sorted(dangerous)),
                    Severity.HIGH,
                    {"capabilities": sorted(dangerous)},
                )
            )

        return findings
