from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, MutableMapping, Sequence

from mcp_agent_safe_protecter.traceability.util import compute_audit_digest


def preview_export_audit_report(
    trace_block: Mapping[str, Any],
    *,
    redact_keys: Sequence[str] = ("password", "token", "secret"),
) -> MutableMapping[str, Any]:
    """导出审计报告预览：敏感键脱敏 + 摘要指纹。"""

    def _redact(obj: Any) -> Any:
        if isinstance(obj, Mapping):
            out: dict[str, Any] = {}
            for k, v in obj.items():
                if any(r in k.lower() for r in redact_keys):
                    out[k] = "[REDACTED]"
                else:
                    out[k] = _redact(v)
            return out
        if isinstance(obj, (list, tuple)):
            return [_redact(x) for x in obj]
        return obj

    clean = _redact(trace_block)
    return {
        "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "payload": clean,
        "digest": compute_audit_digest(clean),
    }
