from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from mcp_agent_safe_protecter.api.app_database import AppDatabase
from mcp_agent_safe_protecter.traceability.store_sqlite import SQLiteTraceStore


def _today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


@dataclass(slots=True)
class TenantLimits:
    max_sessions: int | None
    max_events_per_session: int | None
    max_export_bytes_per_day: int | None


class QuotaManager:
    """
    租户配额与导出计数：持久化在 ``masp_app.sqlite3``（``AppDatabase``）。

    首次启动若配额表为空，会从 ``tenant_quotas.json`` 一次性导入（兼容旧部署）。
    """

    def __init__(self, app_db: AppDatabase) -> None:
        self._db = app_db

    def limits_for(self, tenant_id: str) -> TenantLimits:
        base = self._db.get_quota_row("default")
        over = self._db.get_quota_row(tenant_id)

        def pick(key: str) -> int | None:
            v = over[key]  # type: ignore[literal-required]
            if v is not None:
                return int(v)
            b = base[key]  # type: ignore[literal-required]
            return int(b) if b is not None else None

        return TenantLimits(
            max_sessions=pick("max_sessions"),
            max_events_per_session=pick("max_events_per_session"),
            max_export_bytes_per_day=pick("max_export_bytes_per_day"),
        )

    def allow_new_session(self, tenant_id: str, store: SQLiteTraceStore) -> bool:
        lim = self.limits_for(tenant_id).max_sessions
        if lim is None:
            return True
        return store.count_sessions() < lim

    def allow_append_event(
        self, tenant_id: str, store: SQLiteTraceStore, session_id: str
    ) -> bool:
        lim = self.limits_for(tenant_id).max_events_per_session
        if lim is None:
            return True
        return store.count_events(session_id) < lim

    def export_bytes_used_today(self, tenant_id: str) -> int:
        return self._db.export_bytes_for_day(tenant_id, _today_utc())

    def allow_export(self, tenant_id: str, extra_bytes: int) -> bool:
        lim = self.limits_for(tenant_id).max_export_bytes_per_day
        if lim is None:
            return True
        used = self.export_bytes_used_today(tenant_id)
        return used + extra_bytes <= lim

    def record_export(self, tenant_id: str, byte_count: int) -> None:
        self._db.add_export_bytes(tenant_id, _today_utc(), byte_count)


def resolve_export_root(data_dir: Path) -> Path:
    raw = os.environ.get("MASP_EXPORT_DIR", "").strip()
    if raw:
        return Path(raw)
    return Path(data_dir) / "exports"
