from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


class ExportAuditLog:
    """导出审计：追加 JSON 行到 ``{data_dir}/audit/export_audit.log``。"""

    def __init__(self, data_dir: Path) -> None:
        self._path = Path(data_dir) / "audit"
        self._path.mkdir(parents=True, exist_ok=True)
        self._log = self._path / "export_audit.log"

    def append(self, record: Mapping[str, Any]) -> None:
        line = json.dumps(dict(record), ensure_ascii=False, default=str) + "\n"
        with self._log.open("a", encoding="utf-8") as f:
            f.write(line)


def write_trace_export(
    *,
    export_root: Path,
    tenant_id: str,
    session_id: str,
    principal: str,
    payload: Mapping[str, Any],
    audit: ExportAuditLog,
) -> tuple[str, Path, int]:
    """写入 JSON 文件，返回 (相对展示名, 绝对路径, 字节数)。"""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_tenant = tenant_id.replace("/", "_")[:80]
    dir_path = Path(export_root) / safe_tenant
    dir_path.mkdir(parents=True, exist_ok=True)
    fname = f"trace_{session_id}_{ts}.json"
    path = dir_path / fname
    blob = json.dumps(dict(payload), ensure_ascii=False, default=str).encode("utf-8")
    path.write_bytes(blob)
    audit.append(
        {
            "ts": ts,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "principal": principal,
            "filename": str(Path(safe_tenant) / fname),
            "bytes": len(blob),
        }
    )
    return fname, path, len(blob)
