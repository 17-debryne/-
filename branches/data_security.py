from __future__ import annotations

import re

from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity
from mcp_agent_safe_protecter.shared.pii import find_pii


class DataSecurityDetector:
    """
    分支七：数据安全检测。
    输入输出敏感识别、泄露/非法外传、知识库违规、篡改与未脱敏输出等。
    """

    _LEAK_PATTERNS = (
        re.compile(r"(api[_-]?key|secret|password|token)\s*[:=]\s*[\w\-]{8,}", re.I),
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    )

    _COMMERCIAL_HINTS = (
        "内部定价",
        "未公开财报",
        "并购机密",
        "NDA附件",
        "核心算法参数",
    )

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for label, text in (
            ("input", ctx.last_user_prompt),
            ("output", ctx.last_model_output),
        ):
            if not text:
                continue
            for m in find_pii(text):
                findings.append(
                    Finding(
                        BranchId.DATA_SECURITY,
                        "sensitive_data_" + label,
                        "敏感数据识别",
                        m.kind,
                        Severity.HIGH if label == "output" else Severity.MEDIUM,
                        {"kind": m.kind, "redacted": m.sample},
                    )
                )
            for p in self._LEAK_PATTERNS:
                if p.search(text):
                    findings.append(
                        Finding(
                            BranchId.DATA_SECURITY,
                            "credential_leak_pattern",
                            "疑似密钥/凭证类泄露模式",
                            label,
                            Severity.CRITICAL,
                            {},
                        )
                    )

        kb_flags = ctx.self_check.get("knowledge_base_scan") or {}
        if kb_flags.get("sensitive_violation"):
            findings.append(
                Finding(
                    BranchId.DATA_SECURITY,
                    "kb_sensitive_violation",
                    "知识库敏感内容违规",
                    str(kb_flags.get("detail")),
                    Severity.HIGH,
                    dict(kb_flags),
                )
            )

        if ctx.self_check.get("data_tamper_detected"):
            findings.append(
                Finding(
                    BranchId.DATA_SECURITY,
                    "data_tamper",
                    "数据篡改检测触发",
                    str(ctx.self_check.get("tamper_detail")),
                    Severity.CRITICAL,
                    {},
                )
            )

        if ctx.self_check.get("undesired_raw_read"):
            findings.append(
                Finding(
                    BranchId.DATA_SECURITY,
                    "illegal_read",
                    "非法读取原始敏感存储",
                    str(ctx.self_check.get("read_path")),
                    Severity.HIGH,
                    {},
                )
            )

        if ctx.self_check.get("output_not_redacted") and ctx.last_model_output:
            findings.append(
                Finding(
                    BranchId.DATA_SECURITY,
                    "undesired_output",
                    "输出未脱敏或违反输出策略",
                    "model_output",
                    Severity.HIGH,
                    {},
                )
            )

        kw_list = ctx.self_check.get("commercial_keywords") or []
        if isinstance(kw_list, list) and kw_list:
            extra_kws = tuple(str(k) for k in kw_list if k)
            _all_kw = self._COMMERCIAL_HINTS + extra_kws
        else:
            _all_kw = self._COMMERCIAL_HINTS

        for label, text in (
            ("input", ctx.last_user_prompt),
            ("output", ctx.last_model_output),
        ):
            if not text:
                continue
            for kw in _all_kw:
                if kw and kw in text:
                    findings.append(
                        Finding(
                            BranchId.DATA_SECURITY,
                            "commercial_sensitive_" + label,
                            "商业敏感数据识别（关键词）",
                            kw,
                            Severity.HIGH,
                            {"keyword": kw},
                        )
                    )

        exfil = ctx.self_check.get("exfiltration_channels") or []
        for ch in exfil:
            if ch.get("blocked") is False:
                findings.append(
                    Finding(
                        BranchId.DATA_SECURITY,
                        "illegal_exfiltration",
                        "非法外传通道未阻断",
                        str(ch.get("name")),
                        Severity.CRITICAL,
                        dict(ch),
                    )
                )

        return findings
