from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any, Sequence

from mcp_agent_safe_protecter.core.types import Finding


def _apply_audit_sqlite_max_size_mib(conn: sqlite3.Connection) -> None:
    raw = os.environ.get("MASP_AUDIT_SQLITE_MAX_SIZE_MIB", "").strip()
    if not raw:
        return
    try:
        mib = int(raw)
    except ValueError:
        return
    if mib <= 0:
        return
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    max_pages = max(3, (mib * 1024 * 1024) // page_size)
    conn.execute(f"PRAGMA max_page_count = {int(max_pages)}")


def _finding_payload(f: Finding) -> dict[str, Any]:
    return {
        "branch": f.branch.value,
        "category": f.category,
        "title": f.title,
        "detail": f.detail,
        "severity": f.severity.value,
        "evidence": dict(f.evidence),
        "detected_at": f.detected_at.isoformat(),
    }


class AuditSQLiteStore:
    """
    审计库：每次 ``evaluate``（扫描）一条 ``evaluation_sessions``，关联
    ``findings``、``protection_decisions``、``trace_artifacts``。
    """

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        self._ensure_schema()
        _apply_audit_sqlite_max_size_mib(self._conn)

    @property
    def database_path(self) -> Path:
        return self._path

    def close(self) -> None:
        self._conn.close()

    def _ensure_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS evaluation_sessions (
                id TEXT PRIMARY KEY,
                trace_session_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT NOT NULL,
                blocked INTEGER NOT NULL DEFAULT 0,
                self_heal_triggered INTEGER NOT NULL DEFAULT 0,
                protection_summary_json TEXT NOT NULL DEFAULT '{}',
                context_snapshot_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_evaluation_trace
                ON evaluation_sessions(trace_session_id);
            CREATE INDEX IF NOT EXISTS idx_evaluation_started
                ON evaluation_sessions(started_at DESC);

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evaluation_id TEXT NOT NULL REFERENCES evaluation_sessions(id) ON DELETE CASCADE,
                branch TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_eval ON findings(evaluation_id);

            CREATE TABLE IF NOT EXISTS protection_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evaluation_id TEXT NOT NULL REFERENCES evaluation_sessions(id) ON DELETE CASCADE,
                branch TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_prot_eval ON protection_decisions(evaluation_id);

            CREATE TABLE IF NOT EXISTS trace_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evaluation_id TEXT NOT NULL REFERENCES evaluation_sessions(id) ON DELETE CASCADE,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_trace_art_eval ON trace_artifacts(evaluation_id);
            """
        )
        self._conn.commit()

    def record_evaluation(
        self,
        *,
        trace_session_id: str,
        tenant_id: str,
        agent_id: str,
        started_at: str,
        ended_at: str,
        blocked: bool,
        self_heal_triggered: bool,
        protection_summary: dict[str, Any],
        context_snapshot: dict[str, Any],
        findings: Sequence[Finding],
        trace_artifact: dict[str, Any],
    ) -> str:
        evaluation_id = str(uuid.uuid4())
        by_branch: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for f in findings:
            by_branch[f.branch.value].append(_finding_payload(f))

        _rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        def _max_severity(items: list[dict[str, Any]]) -> str | None:
            if not items:
                return None
            return max(items, key=lambda x: _rank.get(x.get("severity", ""), -1))[
                "severity"
            ]

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO evaluation_sessions (
                    id, trace_session_id, tenant_id, agent_id,
                    started_at, ended_at, blocked, self_heal_triggered,
                    protection_summary_json, context_snapshot_json
                )
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    evaluation_id,
                    trace_session_id,
                    tenant_id,
                    agent_id,
                    started_at,
                    ended_at,
                    int(blocked),
                    int(self_heal_triggered),
                    json.dumps(protection_summary, ensure_ascii=False, default=str),
                    json.dumps(context_snapshot, ensure_ascii=False, default=str),
                ),
            )
            for f in findings:
                self._conn.execute(
                    """
                    INSERT INTO findings (evaluation_id, branch, payload_json)
                    VALUES (?,?,?)
                    """,
                    (
                        evaluation_id,
                        f.branch.value,
                        json.dumps(_finding_payload(f), ensure_ascii=False, default=str),
                    ),
                )
            for branch, items in sorted(by_branch.items()):
                payload = {
                    "branch": branch,
                    "finding_count": len(items),
                    "max_severity": _max_severity(items),
                    "items": items,
                }
                self._conn.execute(
                    """
                    INSERT INTO protection_decisions (evaluation_id, branch, payload_json)
                    VALUES (?,?,?)
                    """,
                    (
                        evaluation_id,
                        branch,
                        json.dumps(payload, ensure_ascii=False, default=str),
                    ),
                )
            self._conn.execute(
                """
                INSERT INTO trace_artifacts (evaluation_id, payload_json)
                VALUES (?,?)
                """,
                (
                    evaluation_id,
                    json.dumps(trace_artifact, ensure_ascii=False, default=str),
                ),
            )
            self._conn.commit()

        self.maybe_prune_old_sessions()
        return evaluation_id

    def maybe_prune_old_sessions(self) -> None:
        raw = os.environ.get("MASP_AUDIT_MAX_SESSIONS", "").strip()
        if not raw:
            return
        try:
            lim = int(raw)
        except ValueError:
            return
        if lim <= 0:
            return
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM evaluation_sessions"
            ).fetchone()
            n = int(row["n"]) if row else 0
            excess = n - lim
            if excess <= 0:
                return
            self._conn.execute(
                """
                DELETE FROM evaluation_sessions WHERE id IN (
                    SELECT id FROM evaluation_sessions ORDER BY started_at ASC LIMIT ?
                )
                """,
                (excess,),
            )
            self._conn.commit()

    def list_recent_evaluations(self, *, limit: int = 20) -> list[dict[str, Any]]:
        lim = max(1, min(limit, 500))
        rows = self._conn.execute(
            """
            SELECT id, trace_session_id, tenant_id, agent_id, started_at, ended_at,
                   blocked, self_heal_triggered, protection_summary_json, context_snapshot_json
            FROM evaluation_sessions
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (lim,),
        ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "id": r["id"],
                    "trace_session_id": r["trace_session_id"],
                    "tenant_id": r["tenant_id"],
                    "agent_id": r["agent_id"],
                    "started_at": r["started_at"],
                    "ended_at": r["ended_at"],
                    "blocked": bool(r["blocked"]),
                    "self_heal_triggered": bool(r["self_heal_triggered"]),
                    "protection_summary": json.loads(r["protection_summary_json"] or "{}"),
                    "context_snapshot": json.loads(r["context_snapshot_json"] or "{}"),
                }
            )
        return out
