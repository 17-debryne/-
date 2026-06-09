from __future__ import annotations

import re
from dataclasses import dataclass

# 中国大陆手机号、身份证简化特征（生产可换专用 NLP/NER）
_CN_MOBILE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_CN_ID = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")


@dataclass(frozen=True, slots=True)
class PIIMatch:
    kind: str
    span: tuple[int, int]
    sample: str


def find_pii(text: str) -> list[PIIMatch]:
    out: list[PIIMatch] = []
    for m in _CN_MOBILE.finditer(text):
        out.append(PIIMatch("mobile_cn", m.span(), m.group()[:3] + "****" + m.group()[-4:]))
    for m in _CN_ID.finditer(text):
        out.append(PIIMatch("id_cn", m.span(), m.group()[:4] + "**********" + m.group()[-4:]))
    return out
