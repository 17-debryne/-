from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from mcp_agent_safe_protecter.traceability.models import TraceLevel


def compute_audit_digest(payload: Mapping[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def canonical_payload_hash(event_type: str, seq: int, payload: Mapping[str, Any]) -> str:
    blob = json.dumps(
        {"event_type": event_type, "seq": seq, "payload": payload},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def merge_traceability_payload(
    base: Mapping[str, Any],
    overlay: Mapping[str, Any],
    *,
    skip_keys: frozenset[str] = frozenset({"session_id"}),
) -> dict[str, Any]:
    """合并存储视图与单次扫描覆盖字段；overlay 优先覆盖同名字典键，列表拼接。"""
    out: dict[str, Any] = dict(base)
    for k, v in overlay.items():
        if k in skip_keys:
            continue
        if k not in out:
            out[k] = v
            continue
        b = out[k]
        if isinstance(b, dict) and isinstance(v, dict):
            merged = dict(b)
            merged.update(v)
            out[k] = merged
        elif isinstance(b, (list, tuple)) and isinstance(v, (list, tuple)):
            out[k] = list(b) + list(v)
        else:
            out[k] = v
    return out


def assign_trace_level(
    *,
    cross_system: bool = False,
    data_integrity_risk: bool = False,
    regulatory_touch: bool = False,
    active_threat: bool = False,
) -> TraceLevel:
    if regulatory_touch or active_threat:
        return TraceLevel.L4
    if data_integrity_risk and cross_system:
        return TraceLevel.L3
    if cross_system or data_integrity_risk:
        return TraceLevel.L2
    return TraceLevel.L1
