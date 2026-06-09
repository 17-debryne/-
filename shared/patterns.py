from __future__ import annotations

import re
from typing import Iterable

# 静态特征库（可外置为 YAML/JSON 并热更新）
PROMPT_INJECTION_PATTERNS: tuple[str, ...] = (
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
    r"disregard\s+(the\s+)?(above|system)",
    r"you\s+are\s+now\s+(DAN|unrestricted)",
    r"<\s*/?\s*system\s*>",
    r"\bjailbreak\b",
    r"reveal\s+(your\s+)?(hidden\s+)?(system\s+)?prompt",
)

PRIVILEGE_ESCALATION_PATTERNS: tuple[str, ...] = (
    r"run\s+as\s+root",
    r"sudo\s+",
    r"grant\s+(me\s+)?(admin|administrator)\s+(access|role)",
    r"elevate\s+privileges",
    r"bypass\s+(auth|authentication|rbac)",
)

SENSITIVE_SHELL_PATTERNS: tuple[str, ...] = (
    r"rm\s+-rf\s+/",
    r"format\s+[a-z]:",
    r"mkfs\.",
    r"dd\s+if=",
    r":\(\)\s*\{\s*:\|:&\s*\}\s*;",
    r"curl\s+.+\|\s*(ba)?sh",
)


def compile_patterns(patterns: Iterable[str]) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns]
