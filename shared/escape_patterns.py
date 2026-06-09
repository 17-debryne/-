from __future__ import annotations

import re

# 角色逃逸 / 越狱 / 绕过约束（可与威胁情报库合并维护）
ROLE_ESCAPE_PATTERNS: tuple[str, ...] = (
    r"you\s+are\s+no\s+longer\s+(an?\s+)?assistant",
    r"forget\s+your\s+(rules|guidelines|policy)",
    r"switch\s+to\s+(developer|unrestricted|god)\s+mode",
    r"override\s+(safety|alignment|policy)",
    r"ignore\s+(your\s+)?(system\s+)?role",
    r"new\s+persona\s*[:]",
    r"不再遵守\s*(安全|对齐|约束)",
)

JAILBREAK_PATTERNS: tuple[str, ...] = (
    r"\bDAN\b",
    r"hypothetical\s+scenario",
    r"for\s+educational\s+purposes\s+only",
    r"without\s+ethical\s+constraints",
)

CONSTRAINT_BYPASS_PATTERNS: tuple[str, ...] = (
    r"bypass\s+(the\s+)?(filter|guardrail|moderation)",
    r"workaround\s+(policy|block)",
    r"encode\s+(the\s+)?(payload|instruction)\s+in\s+base64",
)

SECURITY_POLICY_TAMPER_PATTERNS: tuple[str, ...] = (
    r"disable\s+(the\s+)?security\s+(policy|module|scanner)",
    r"turn\s+off\s+(the\s+)?(firewall|edr|monitoring|audit)",
    r"setSecurityEnabled\s*\(\s*false\s*\)",
    r"SECURITY_DETECTION\s*=\s*false",
    r"\bmasp\s*(scan|detect|guard)\s*(off|disabled|false)\b",
    r"关闭\s*(安全\s*)?(检测|扫描|审计|护栏)",
    r"绕过\s*(风控|策略引擎|合规校验)",
    r"guardrail(_enabled)?\s*[:=]\s*false",
)

HIGH_PRIV_CMD_PATTERNS: tuple[str, ...] = (
    r"\bnet\s+user\b.*/add",
    r"\bcd\s+/d\s+\\\\?\\.\\",
    r"\breg\s+add\b.*/f",
    r"\bwevtutil\s+cl\b",
    r"\bchmod\s+777\b",
    r"\bsetenforce\s+0\b",
    r"\brkdump\b|\bdebugfs\b",
    r"\busermod\s+-aG\s+sudo\b",
    r"\bcdk\s+deploy\b.*--require-approval\s+never",
)


def compile_group(patterns: tuple[str, ...]) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns]
