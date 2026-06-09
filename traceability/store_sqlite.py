from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from mcp_agent_safe_protecter.traceability.models import StoredTraceEvent, TraceSession
from mcp_agent_safe_protecter.traceability.util import canonical_payload_hash


_GENESIS = "GENESIS"


class SQLiteTraceStore:
    """
    溯源事件持久化：SQLite + WAL，事件仅追加；行哈希链用于简易防篡改校验。
    """

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.Lock()
        self._ensure_schema()

    def close(self) -> None:
        self._conn.close()

    def checkpoint_wal(self) -> None:
        """将 WAL 落盘并尝试截断（降低旁路 ``-wal`` 文件体积）；忽略不支持的环境。"""
        with self._lock:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                try:
                    self._conn.execute("PRAGMA wal_checkpoint(FULL)")
                except sqlite3.Error:
                    pass

    def _ensure_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS trace_sessions (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                meta_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS trace_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES trace_sessions(id) ON DELETE CASCADE,
                seq INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                row_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(session_id, seq)
            );
            CREATE INDEX IF NOT EXISTS idx_trace_events_session_seq
                ON trace_events(session_id, seq);
            """
        )
        self._conn.commit()

    def create_session(
        self,
        tenant_id: str,
        agent_id: str,
        *,
        meta: Mapping[str, Any] | None = None,
        session_id: str | None = None,
    ) -> str:
        sid = session_id or str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        payload = dict(meta or {})
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO trace_sessions (id, tenant_id, agent_id, created_at, meta_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (sid, tenant_id, agent_id, now, json.dumps(payload, ensure_ascii=False)),
            )
            self._conn.commit()
        return sid

    def get_session(self, session_id: str) -> TraceSession | None:
        row = self._conn.execute(
            "SELECT id, tenant_id, agent_id, created_at, meta_json FROM trace_sessions WHERE id=?",
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        return TraceSession(
            id=row["id"],
            tenant_id=row["tenant_id"],
            agent_id=row["agent_id"],
            created_at=datetime.fromisoformat(row["created_at"].replace("Z", "+00:00")),
            meta=json.loads(row["meta_json"] or "{}"),
        )

    def append_event(self, session_id: str, event_type: str, payload: Mapping[str, Any]) -> int:
        """写入一条溯源事件，返回 seq。"""
        payload_dict = dict(payload)
        raw_default = os.environ.get("MASP_MAX_EVENT_PAYLOAD_BYTES", "524288").strip()
        try:
            max_payload = int(raw_default)
        except ValueError:
            max_payload = 524288
        payload_blob = json.dumps(payload_dict, ensure_ascii=False, default=str)
        if max_payload > 0 and len(payload_blob.encode("utf-8")) > max_payload:
            raise ValueError(
                f"事件 payload 序列化后超过上限 {max_payload} 字节（MASP_MAX_EVENT_PAYLOAD_BYTES）"
            )
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with self._lock:
            cur = self._conn.execute(
                "SELECT seq, row_hash FROM trace_events WHERE session_id=? ORDER BY seq DESC LIMIT 1",
                (session_id,),
            ).fetchone()
            prev_hash = str(cur["row_hash"]) if cur else _GENESIS
            seq = int(cur["seq"]) + 1 if cur else 1
            rh = canonical_payload_hash(event_type, seq, payload_dict)
            chain_input = f"{prev_hash}|{rh}"
            row_hash = canonical_payload_hash("__chain__", seq, {"link": chain_input})
            self._conn.execute(
                """
                INSERT INTO trace_events
                    (session_id, seq, event_type, payload_json, prev_hash, row_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    seq,
                    event_type,
                    payload_blob,
                    prev_hash,
                    row_hash,
                    now,
                ),
            )
            self._conn.commit()
        return seq

    def iter_events(self, session_id: str) -> Iterator[StoredTraceEvent]:
        rows = self._conn.execute(
            """
            SELECT seq, event_type, payload_json, prev_hash, row_hash, created_at
            FROM trace_events WHERE session_id=? ORDER BY seq ASC
            """,
            (session_id,),
        )
        for row in rows:
            yield StoredTraceEvent(
                seq=row["seq"],
                event_type=row["event_type"],
                payload=json.loads(row["payload_json"]),
                prev_hash=row["prev_hash"],
                row_hash=row["row_hash"],
                created_at=datetime.fromisoformat(row["created_at"].replace("Z", "+00:00")),
            )

    def verify_chain(self, session_id: str) -> tuple[bool, str]:
        """校验哈希链接连续性（检测非法删改）。"""
        prev = _GENESIS
        for ev in self.iter_events(session_id):
            rh = canonical_payload_hash(ev.event_type, ev.seq, ev.payload)
            expected_prev = prev
            if ev.prev_hash != expected_prev:
                return False, f"prev_hash mismatch at seq={ev.seq}"
            chain_input = f"{ev.prev_hash}|{rh}"
            expected_row = canonical_payload_hash("__chain__", ev.seq, {"link": chain_input})
            if ev.row_hash != expected_row:
                return False, f"row_hash mismatch at seq={ev.seq}"
            prev = ev.row_hash
        return True, "ok"

    def build_traceability_view(self, session_id: str) -> dict[str, Any]:
        """将追加事件还原为 ``TraceabilityDetector`` 所需的 traceability 字典结构。"""
        operation_chain: dict[str, Any] = {"hops": []}
        flow_chain: dict[str, Any] = {"stages": []}
        asset_resources: dict[str, Any] = {
            "soft_assets": [],
            "hard_assets": [],
            "resource_usage": [],
            "config_changes": [],
        }
        compliance_audit: dict[str, Any] = {}
        data_mutations: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        threat_events: list[dict[str, Any]] = []
        incident_loop: dict[str, Any] = {}

        for ev in self.iter_events(session_id):
            et = ev.event_type
            p = ev.payload
            if et == "operation_chain_meta":
                operation_chain.update({k: v for k, v in p.items() if k != "hops"})
            elif et == "operation_hop":
                operation_chain.setdefault("hops", []).append(p)
            elif et == "flow_chain_meta":
                flow_chain.update({k: v for k, v in p.items() if k != "stages"})
            elif et == "flow_stage":
                flow_chain.setdefault("stages", []).append(p)
            elif et == "data_mutation":
                data_mutations.append(p)
            elif et == "asset_soft":
                asset_resources["soft_assets"].append(p)
            elif et == "asset_hard":
                asset_resources["hard_assets"].append(p)
            elif et == "resource_usage":
                asset_resources["resource_usage"].append(p)
            elif et == "config_change":
                asset_resources["config_changes"].append(p)
            elif et == "compliance_audit":
                compliance_audit.update(p)
            elif et == "error_record":
                errors.append(p)
            elif et == "threat_event":
                threat_events.append(p)
            elif et == "incident_loop":
                for k, v in p.items():
                    if k == "correlation_links" and isinstance(v, dict):
                        base = incident_loop.get("correlation_links")
                        if isinstance(base, dict):
                            merged = dict(base)
                            merged.update(v)
                            incident_loop["correlation_links"] = merged
                        else:
                            incident_loop["correlation_links"] = dict(v)
                    else:
                        incident_loop[k] = v

        out: dict[str, Any] = {}
        if operation_chain.get("hops") or operation_chain.get("expected_sequence"):
            oc = {"hops": tuple(operation_chain.get("hops") or ())}
            for k, v in operation_chain.items():
                if k != "hops":
                    oc[k] = v
            out["operation_chain"] = oc
        if flow_chain.get("stages") or flow_chain.get("trace_id"):
            fc = {"stages": tuple(flow_chain.get("stages") or ())}
            for k, v in flow_chain.items():
                if k != "stages":
                    fc[k] = v
            out["flow_chain"] = fc
        if data_mutations:
            out["data_mutations"] = tuple(data_mutations)
        ar = {
            k: tuple(v)
            for k, v in asset_resources.items()
            if v
        }
        if ar:
            out["asset_resources"] = ar
        if compliance_audit:
            out["compliance_audit"] = compliance_audit
        if errors:
            out["errors"] = tuple(errors)
        if threat_events:
            out["threats"] = {"events": tuple(threat_events)}
        if incident_loop:
            out["incident_loop"] = incident_loop

        return out

    def list_sessions(
        self,
        *,
        tenant_id: str | None = None,
        limit: int = 200,
    ) -> Sequence[TraceSession]:
        q = "SELECT id, tenant_id, agent_id, created_at, meta_json FROM trace_sessions"
        args: list[Any] = []
        if tenant_id:
            q += " WHERE tenant_id=?"
            args.append(tenant_id)
        q += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        rows = self._conn.execute(q, args).fetchall()
        out: list[TraceSession] = []
        for row in rows:
            out.append(
                TraceSession(
                    id=row["id"],
                    tenant_id=row["tenant_id"],
                    agent_id=row["agent_id"],
                    created_at=datetime.fromisoformat(row["created_at"].replace("Z", "+00:00")),
                    meta=json.loads(row["meta_json"] or "{}"),
                )
            )
        return out

    def count_sessions(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM trace_sessions").fetchone()
        return int(row["n"]) if row else 0

    def count_events(self, session_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM trace_events WHERE session_id=?",
            (session_id,),
        ).fetchone()
        return int(row["n"]) if row else 0
