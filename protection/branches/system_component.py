from __future__ import annotations

from typing import Mapping

from mcp_agent_safe_protecter.core.types import Severity
from mcp_agent_safe_protecter.protection.context import ProtectionEvaluationContext
from mcp_agent_safe_protecter.protection.types import ProtectionBranchId, ProtectionSignal


class SystemComponentProtection:
    """
    分支① 系统与组件漏洞破坏防护。
    智能体本体、依赖库、插件、运行环境：漏洞利用、溢出、后门挂载、恶意代码、配置篡改；
    防止被攻破后篡改程序、破坏运行环境。
    """

    def analyze(self, ctx: ProtectionEvaluationContext) -> list[ProtectionSignal]:
        s: list[ProtectionSignal] = []
        sc = ctx.scan
        sig = sc.self_check.get("system_component") or {}
        if isinstance(sig, dict):
            if sig.get("buffer_overflow_attempt"):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.SYSTEM_COMPONENT,
                        "buffer_overflow_block",
                        "漏洞溢出利用尝试 — 建议立即阻断进程与连接",
                        str(sig.get("detail", "")),
                        Severity.CRITICAL,
                        dict(sig),
                        ("isolate_session", "block_tool", "alert_soc"),
                    )
                )
            if sig.get("backdoor_implant_suspected"):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.SYSTEM_COMPONENT,
                        "backdoor_implant_block",
                        "后门或持久化植入可疑 — 建议隔离与完整性回滚",
                        str(sig.get("path", "")),
                        Severity.CRITICAL,
                        dict(sig),
                        ("isolate_session", "rollback_config", "alert_soc"),
                    )
                )
            if sig.get("malicious_code_mount"):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.SYSTEM_COMPONENT,
                        "malicious_mount_block",
                        "恶意代码挂载 / 不可信模块加载",
                        str(sig.get("module", "")),
                        Severity.CRITICAL,
                        dict(sig),
                        ("block_tool", "revoke_token"),
                    )
                )
            if sig.get("post_exploit_env_destroy"):
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.SYSTEM_COMPONENT,
                        "post_exploit_env_guard",
                        "漏洞攻破后环境破坏行为 — 建议冻结主机与断电预案",
                        str(sig.get("detail", "")),
                        Severity.CRITICAL,
                        dict(sig),
                        ("isolate_session", "alert_soc"),
                    )
                )

        if sc.env_snapshot.get("LD_PRELOAD") or sc.env_snapshot.get("DYLD_INSERT_LIBRARIES"):
            s.append(
                ProtectionSignal(
                    ProtectionBranchId.SYSTEM_COMPONENT,
                    "dynamic_linker_hijack_guard",
                    "动态链接劫持环境变量存在 — 阻止特权进程启动",
                    "LD_PRELOAD / DYLD_INSERT_LIBRARIES",
                    Severity.HIGH,
                    dict(sc.env_snapshot),
                    ("reject_request", "block_tool"),
                )
            )

        for path, expected in sc.file_manifest.items():
            actual = sc.file_actual_hashes.get(path)
            if actual is not None and actual != expected:
                s.append(
                    ProtectionSignal(
                        ProtectionBranchId.SYSTEM_COMPONENT,
                        "binary_integrity_guard",
                        "程序/组件运行镜像与基线不一致 — 阻断加载并回滚",
                        path,
                        Severity.CRITICAL,
                        {"path": path, "expected": expected, "actual": actual},
                        ("rollback_config", "block_tool", "alert_soc"),
                    )
                )

        plugs = sc.self_check.get("plugin_integrity") or []
        if isinstance(plugs, list):
            for p in plugs:
                if not isinstance(p, Mapping):
                    continue
                if p.get("unsigned") or p.get("tampered"):
                    s.append(
                        ProtectionSignal(
                            ProtectionBranchId.SYSTEM_COMPONENT,
                            "plugin_load_guard",
                            "插件未签名或被篡改 — 拒绝加载",
                            str(p.get("name", "")),
                            Severity.HIGH,
                            dict(p),
                            ("block_tool", "reject_request"),
                        )
                    )

        return s
