from __future__ import annotations

import json
import re
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

from mcp_agent_safe_protecter.core.ai_anomaly import HeuristicAnomalyDiscriminator
from mcp_agent_safe_protecter.core.baseline import BehavioralBaseline
from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity
from mcp_agent_safe_protecter.shared.patterns import (
    PROMPT_INJECTION_PATTERNS,
    PRIVILEGE_ESCALATION_PATTERNS,
    SENSITIVE_SHELL_PATTERNS,
    compile_patterns,
)

# 恶意/高风险外部请求特征（可接威胁情报订阅）
_DEFAULT_BLOCKLIST_HOST_SUFFIXES: frozenset[str] = frozenset(
    {".onion", ".tk", ".gq", ".ml", ".cf"}
)
_SUSPICIOUS_PLUGIN_PREFIXES: tuple[str, ...] = (
    "shadow_",
    "mal_",
    "exfil_",
    "_hidden",
)

# 工具参数中的动态执行 / 远程载荷迹象（指令越权补充）
_TOOL_PAYLOAD_RISK: re.Pattern[str] = re.compile(
    r"\b(eval|exec|compile|__import__|subprocess|os\.system|powershell\s+-enc|"
    r"curl\s+.+\|\s*(ba)?sh|wget\s+.+\|\s*sh)\b",
    re.IGNORECASE,
)

_SENSITIVE_HTTP_METHODS: frozenset[str] = frozenset({"TRACE", "TRACK"})


class GlobalThreatDetector:
    """
    分支一：全域威胁检测。
    组合 静态特征库 + 行为基线 + AI/启发式异常判别。
    """

    def __init__(
        self,
        *,
        behavioral_baseline: BehavioralBaseline | None = None,
        ai_discriminator: HeuristicAnomalyDiscriminator | None = None,
        blocklist_hosts: frozenset[str] | None = None,
        model_poison_paths: Sequence[str] | None = None,
    ) -> None:
        self._inj = compile_patterns(PROMPT_INJECTION_PATTERNS)
        self._priv = compile_patterns(PRIVILEGE_ESCALATION_PATTERNS)
        self._shell = compile_patterns(SENSITIVE_SHELL_PATTERNS)
        self.baseline = behavioral_baseline or BehavioralBaseline()
        self.ai = ai_discriminator or HeuristicAnomalyDiscriminator()
        self._blocklist = blocklist_hosts or frozenset()
        self._poison_paths = frozenset(model_poison_paths or ())

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        text_blob = " ".join(
            x for x in (ctx.last_user_prompt, ctx.last_model_output) if x
        )
        inj_hits = self._count_matches(self._inj, text_blob)
        priv_hits = self._count_matches(self._priv, text_blob)
        shell_hits = self._count_matches(self._shell, text_blob)

        if inj_hits:
            findings.append(
                Finding(
                    BranchId.GLOBAL_THREAT,
                    "prompt_injection",
                    "检测到疑似 Prompt 注入模式",
                    f"命中 {inj_hits} 条静态特征",
                    Severity.HIGH,
                    {"hits": inj_hits},
                )
            )
        if priv_hits:
            findings.append(
                Finding(
                    BranchId.GLOBAL_THREAT,
                    "instruction_privilege_escalation",
                    "检测到指令越权/提权诱导",
                    f"命中 {priv_hits} 条模式",
                    Severity.HIGH,
                    {"hits": priv_hits},
                )
            )

        unknown_tools = 0
        risky_tool_payloads = 0
        for call in ctx.tool_calls:
            name = str(call.get("name") or call.get("tool") or "")
            if self.baseline.tool_name_outlier(name):
                unknown_tools += 1
            if any(name.lower().startswith(p) for p in _SUSPICIOUS_PLUGIN_PREFIXES):
                findings.append(
                    Finding(
                        BranchId.GLOBAL_THREAT,
                        "malicious_plugin_call",
                        "可疑插件/工具名（静态前缀规则）",
                        name,
                        Severity.MEDIUM,
                        {"tool": name},
                    )
                )
            raw_args = call.get("arguments")
            if raw_args is None:
                raw_args = call.get("args")
            blob = ""
            if isinstance(raw_args, str):
                blob = raw_args
            elif isinstance(raw_args, dict):
                blob = json.dumps(raw_args, ensure_ascii=False)
            elif raw_args is not None:
                blob = str(raw_args)
            if blob and _TOOL_PAYLOAD_RISK.search(blob):
                risky_tool_payloads += 1
                findings.append(
                    Finding(
                        BranchId.GLOBAL_THREAT,
                        "malicious_tool_arguments",
                        "恶意插件调用 / 敏感指令执行风险（工具参数）",
                        name or "unknown_tool",
                        Severity.HIGH,
                        {"tool": name, "pattern": "dynamic_exec_or_shell_pipeline"},
                    )
                )

        if shell_hits:
            findings.append(
                Finding(
                    BranchId.GLOBAL_THREAT,
                    "sensitive_command",
                    "敏感指令执行风险",
                    "用户或模型输出包含高危 shell 片段",
                    Severity.CRITICAL,
                    {"hits": shell_hits},
                )
            )

        ext_block = self._external_malicious_requests(ctx.raw_http_requests)
        findings.extend(ext_block)
        findings.extend(self._risky_http_methods(ctx.raw_http_requests))

        if self._poison_paths:
            findings.extend(self._model_poisoning_scan(ctx))

        feat: dict[str, Any] = {
            "prompt_injection_hits": inj_hits,
            "privilege_escalation_hits": priv_hits,
            "sensitive_command_hits": shell_hits,
            "unknown_tool_calls": unknown_tools,
            "risky_tool_payloads": risky_tool_payloads,
            "external_blocklisted_host": len(ext_block),
        }
        score = self.ai.score(feat)
        if self.ai.is_anomaly(feat):
            findings.append(
                Finding(
                    BranchId.GLOBAL_THREAT,
                    "ai_risk_threat",
                    "综合风险威胁（特征+基线+判别器）",
                    f"异常评分 {score:.2f} 超过阈值 {self.ai.threshold}",
                    Severity.HIGH if score < 0.85 else Severity.CRITICAL,
                    {"score": score, "features": feat},
                )
            )

        return findings

    @staticmethod
    def _count_matches(patterns: Sequence[Any], text: str) -> int:
        if not text:
            return 0
        return sum(1 for p in patterns if p.search(text))

    def _external_malicious_requests(
        self, reqs: Sequence[Mapping[str, Any]]
    ) -> list[Finding]:
        out: list[Finding] = []
        for r in reqs:
            url = str(r.get("url") or "")
            if not url:
                continue
            try:
                host = (urlparse(url).hostname or "").lower()
            except ValueError:
                continue
            if any(host.endswith(s) for s in _DEFAULT_BLOCKLIST_HOST_SUFFIXES):
                out.append(
                    Finding(
                        BranchId.GLOBAL_THREAT,
                        "external_malicious_request",
                        "外部请求命中高风险域名后缀规则",
                        url,
                        Severity.HIGH,
                        {"host": host},
                    )
                )
            if host in self._blocklist:
                out.append(
                    Finding(
                        BranchId.GLOBAL_THREAT,
                        "external_blocklist",
                        "外部请求命中自定义黑名单",
                        url,
                        Severity.HIGH,
                        {"host": host},
                    )
                )
        return out

    def _risky_http_methods(
        self, reqs: Sequence[Mapping[str, Any]]
    ) -> list[Finding]:
        out: list[Finding] = []
        for r in reqs:
            method = str(r.get("method") or r.get("verb") or "").upper()
            url = str(r.get("url") or "")
            if method in _SENSITIVE_HTTP_METHODS:
                out.append(
                    Finding(
                        BranchId.GLOBAL_THREAT,
                        "risky_http_method",
                        "异常 HTTP 方法（外部恶意请求攻击 — 方法面）",
                        f"{method} {url}",
                        Severity.MEDIUM,
                        {"method": method, "url": url},
                    )
                )
            admin_markers = ("/admin", "/internal", "/actuator", "/.env")
            if method == "DELETE" and url and any(m in url.lower() for m in admin_markers):
                out.append(
                    Finding(
                        BranchId.GLOBAL_THREAT,
                        "destructive_admin_request",
                        "破坏性请求指向管理/敏感路径",
                        url,
                        Severity.HIGH,
                        {"method": method},
                    )
                )
        return out

    def _model_poisoning_scan(self, ctx: ScanContext) -> list[Finding]:
        """若 manifest 中出现非预期路径，提示模型/权重完整性风险。"""
        findings: list[Finding] = []
        paths = set(ctx.file_actual_hashes) | set(ctx.file_manifest)
        unexpected = paths & self._poison_paths
        for p in unexpected:
            findings.append(
                Finding(
                    BranchId.GLOBAL_THREAT,
                    "model_poisoning_suspect",
                    "模型文件路径命中投毒观察清单",
                    p,
                    Severity.MEDIUM,
                    {"path": p},
                )
            )
        return findings
