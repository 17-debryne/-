"""将 HTTP/API 的 overlay JSON 合并进 ``ScanContext``（支持各安全检测分支字段）。"""

from __future__ import annotations

from dataclasses import fields, replace
from typing import Any, Mapping

from mcp_agent_safe_protecter.core.types import ScanContext

_SCAN_CONTEXT_FIELD_NAMES: frozenset[str] = frozenset(f.name for f in fields(ScanContext))
_SEQ_FIELDS: frozenset[str] = frozenset(
    {
        "tool_calls",
        "task_states",
        "behavior_events",
        "raw_http_requests",
    }
)
_MUTABLE_MAP_FIELDS: frozenset[str] = frozenset({"config_snapshots"})


def merge_overlay_into_scan_context(
    ctx: ScanContext, overlay: Mapping[str, Any] | None
) -> ScanContext:
    """
    - 与 ``ScanContext`` 同名的键写入对应字段（列表会转为 tuple）。
    - ``traceability`` 键若为 dict，与会话内已有 traceability 深度合并。
    - 其余未知键合并入 ``traceability``（兼容旧客户端仅传溯源扩展字段）。
    """
    if not overlay:
        return ctx

    updates: dict[str, Any] = {}
    trace_patch: dict[str, Any] = {}

    for key, raw in overlay.items():
        if key == "traceability" and isinstance(raw, dict):
            trace_patch.update(raw)
            continue
        if key in _SCAN_CONTEXT_FIELD_NAMES:
            if key == "now":
                continue
            if key in _SEQ_FIELDS:
                updates[key] = tuple(raw) if isinstance(raw, list) else raw
            elif key == "metrics" and isinstance(raw, dict):
                updates[key] = {k: float(v) for k, v in raw.items()}
            elif key in _MUTABLE_MAP_FIELDS and isinstance(raw, dict):
                merged = dict(ctx.config_snapshots)
                merged.update(raw)
                updates[key] = merged
            else:
                updates[key] = raw
        else:
            trace_patch[key] = raw

    new_trace = dict(ctx.traceability)
    new_trace.update(trace_patch)
    updates["traceability"] = new_trace

    return replace(ctx, **updates)
