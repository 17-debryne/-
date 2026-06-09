from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from fastapi import Request


class SecurityAuditLog:
    """敏感操作审计：追加 JSON 行到 ``{data_dir}/security_audit/events.jsonl``。"""

    def __init__(self, data_dir: Path) -> None:
        self._dir = Path(data_dir) / "security_audit"
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / "events.jsonl"
        self._lock = threading.Lock()

    @property
    def log_path(self) -> Path:
        return self._path

    def append(self, record: Mapping[str, Any]) -> None:
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        line = json.dumps({"ts": ts, **dict(record)}, ensure_ascii=False, default=str) + "\n"
        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line)


def audit_security(request: Request | None, event_type: str, **fields: Any) -> None:
    """写入安全审计（``request`` 可为 None，用于无请求上下文路径）。"""
    sal: SecurityAuditLog | None = None
    if request is not None:
        sal = getattr(request.app.state, "security_audit", None)
        rid = getattr(getattr(request, "state", None), "request_id", None)
        if rid:
            fields.setdefault("request_id", rid)
        client = request.client.host if request.client else ""
        if client:
            fields.setdefault("client_host", client)
        xff = request.headers.get("x-forwarded-for")
        if xff:
            fields.setdefault("x_forwarded_for", xff.split(",")[0].strip()[:128])
    if sal is None:
        return
    sal.append({"event": event_type, **fields})
