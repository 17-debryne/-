from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from mcp_agent_safe_protecter.traceability.store_sqlite import SQLiteTraceStore

_TENANT_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def configured_trace_store_cache_max() -> int | None:
    """环境变量 ``MASP_TRACE_STORE_CACHE_MAX``：>0 时限制内存中缓存的租户连接数（FIFO 驱逐）。"""
    raw = os.environ.get("MASP_TRACE_STORE_CACHE_MAX", "").strip()
    if not raw:
        return None
    try:
        n = int(raw)
    except ValueError:
        return None
    return n if n > 0 else None


class TenantTraceRegistry:
    """
    多租户物理分库：每个租户独立 SQLite 文件 ``{data_dir}/tenants/{tenant_id}.sqlite3``。

    内存中缓存已打开的 ``SQLiteTraceStore``（按 ``tenant_id``），可通过
    ``evict_trace_store_cache`` 释放连接并可选收缩 WAL。
    """

    def __init__(self, data_dir: str | Path) -> None:
        self.data_dir = Path(data_dir)
        self._tenants_dir = self.data_dir / "tenants"
        self._tenants_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, SQLiteTraceStore] = {}

    @staticmethod
    def normalize_tenant_id(tenant_id: str) -> str:
        if not _TENANT_RE.fullmatch(tenant_id or ""):
            raise ValueError(
                "tenant_id 仅允许 1–64 位字母数字、下划线或短横线",
            )
        return tenant_id

    @staticmethod
    def validate_tenant_id(tenant_id: str) -> str:
        try:
            return TenantTraceRegistry.normalize_tenant_id(tenant_id)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    def db_path(self, tenant_id: str) -> Path:
        tid = self.validate_tenant_id(tenant_id)
        return self._tenants_dir / f"{tid}.sqlite3"

    def _evict_one_cached_trace_store(self, *, checkpoint_wal: bool = True) -> str | None:
        """按插入顺序驱逐一个缓存项（用于容量上限）；无可驱逐时返回 None。"""
        if not self._cache:
            return None
        oldest_tid = next(iter(self._cache))
        store = self._cache.pop(oldest_tid)
        if checkpoint_wal:
            store.checkpoint_wal()
        store.close()
        return oldest_tid

    def _enforce_trace_store_cache_capacity(self, incoming_tid: str) -> None:
        max_n = configured_trace_store_cache_max()
        if max_n is None or incoming_tid in self._cache:
            return
        while len(self._cache) >= max_n:
            self._evict_one_cached_trace_store(checkpoint_wal=True)

    def get_store(self, tenant_id: str) -> SQLiteTraceStore:
        tid = self.validate_tenant_id(tenant_id)
        if tid not in self._cache:
            self._enforce_trace_store_cache_capacity(tid)
            self._cache[tid] = SQLiteTraceStore(self.db_path(tid))
        return self._cache[tid]

    def trace_store_cache_stats(self) -> dict[str, Any]:
        return {
            "scope": "trace_stores",
            "cached_count": len(self._cache),
            "cached_tenant_ids": sorted(self._cache.keys()),
            "cache_max": configured_trace_store_cache_max(),
        }

    def evict_trace_store_cache(
        self,
        tenant_ids: list[str] | None,
        *,
        checkpoint_wal: bool = True,
    ) -> dict[str, Any]:
        """
        关闭并移除内存中的租户溯源连接缓存。

        - ``tenant_ids`` 为 ``None`` 或空列表：驱逐全部缓存。
        - 否则仅驱逐列表中当前已缓存的租户（未知租户忽略）。
        """
        evicted: list[str] = []
        if tenant_ids:
            normalized: list[str] = []
            for raw in tenant_ids:
                normalized.append(self.normalize_tenant_id(raw))
            targets = [t for t in normalized if t in self._cache]
            for tid in targets:
                store = self._cache.pop(tid)
                if checkpoint_wal:
                    store.checkpoint_wal()
                store.close()
                evicted.append(tid)
            return {
                "scope": "trace_stores",
                "checkpoint_wal": checkpoint_wal,
                "evicted_tenant_ids": evicted,
            }

        for tid, store in list(self._cache.items()):
            if checkpoint_wal:
                store.checkpoint_wal()
            store.close()
            evicted.append(tid)
        self._cache.clear()
        return {
            "scope": "trace_stores",
            "checkpoint_wal": checkpoint_wal,
            "evicted_tenant_ids": evicted,
        }

    def close_all(self) -> None:
        for store in self._cache.values():
            store.close()
        self._cache.clear()
