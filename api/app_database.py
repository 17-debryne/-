from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


def login_throttle_key(login: str) -> str:
    """登录标识规范化后的 SHA256 hex（用于节流表主键，不明文存邮箱/用户名）。"""
    return hashlib.sha256(login.strip().lower().encode("utf-8")).hexdigest()


class AppDatabase:
    """
    应用级元数据库：``{MASP_DATA_DIR}/masp_app.sqlite3``。

    - 租户配额（替代 ``tenant_quotas.json``，避免配置文件膨胀且便于原子更新）
    - 按日导出字节计数（替代 ``quota_usage/*.json``，防止目录下文件无限增长）
    - 兼容旧版 JWT 用户的口令表（替代 ``auth/users.json``）
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

    def close(self) -> None:
        self._conn.close()

    @property
    def path(self) -> Path:
        return self._path

    def _ensure_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS tenant_quotas (
                tenant_id TEXT PRIMARY KEY,
                max_sessions INTEGER,
                max_events_per_session INTEGER,
                max_export_bytes_per_day INTEGER
            );
            CREATE TABLE IF NOT EXISTS export_usage (
                tenant_id TEXT NOT NULL,
                day TEXT NOT NULL,
                export_bytes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (tenant_id, day)
            );
            CREATE INDEX IF NOT EXISTS idx_export_usage_day ON export_usage(day);
            CREATE TABLE IF NOT EXISTS jwt_legacy_users (
                username TEXT PRIMARY KEY,
                salt TEXT NOT NULL,
                hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_throttle (
                login_key_hash TEXT PRIMARY KEY,
                fail_count INTEGER NOT NULL DEFAULT 0,
                window_start INTEGER NOT NULL,
                locked_until INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        self._conn.commit()

    def quota_row_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM tenant_quotas").fetchone()
        return int(row["n"]) if row else 0

    def migrate_quotas_from_json(self, json_path: Path) -> None:
        """仅在配额表为空且 JSON 存在时导入一次。"""
        if self.quota_row_count() > 0 or not json_path.is_file():
            return
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        if not isinstance(raw, dict):
            return
        with self._lock:
            for tid, cfg in raw.items():
                if not isinstance(tid, str) or not isinstance(cfg, dict):
                    continue
                self._upsert_quota_unlocked(
                    tid,
                    cfg.get("max_sessions"),
                    cfg.get("max_events_per_session"),
                    cfg.get("max_export_bytes_per_day"),
                )
            self._conn.commit()

    def _upsert_quota_unlocked(
        self,
        tenant_id: str,
        max_sessions: Any,
        max_events_per_session: Any,
        max_export_bytes_per_day: Any,
    ) -> None:
        def _int_or_none(v: Any) -> int | None:
            if v is None:
                return None
            try:
                return int(v)
            except (TypeError, ValueError):
                return None

        self._conn.execute(
            """
            INSERT INTO tenant_quotas (
                tenant_id, max_sessions, max_events_per_session, max_export_bytes_per_day
            ) VALUES (?,?,?,?)
            ON CONFLICT(tenant_id) DO UPDATE SET
                max_sessions = excluded.max_sessions,
                max_events_per_session = excluded.max_events_per_session,
                max_export_bytes_per_day = excluded.max_export_bytes_per_day
            """,
            (
                tenant_id,
                _int_or_none(max_sessions),
                _int_or_none(max_events_per_session),
                _int_or_none(max_export_bytes_per_day),
            ),
        )

    def get_quota_row(self, tenant_id: str) -> dict[str, int | None]:
        row = self._conn.execute(
            """
            SELECT max_sessions, max_events_per_session, max_export_bytes_per_day
            FROM tenant_quotas WHERE tenant_id = ?
            """,
            (tenant_id,),
        ).fetchone()
        if row is None:
            return {
                "max_sessions": None,
                "max_events_per_session": None,
                "max_export_bytes_per_day": None,
            }
        return {
            "max_sessions": row["max_sessions"],
            "max_events_per_session": row["max_events_per_session"],
            "max_export_bytes_per_day": row["max_export_bytes_per_day"],
        }

    def export_bytes_for_day(self, tenant_id: str, day: str) -> int:
        row = self._conn.execute(
            "SELECT export_bytes FROM export_usage WHERE tenant_id=? AND day=?",
            (tenant_id, day),
        ).fetchone()
        return int(row["export_bytes"]) if row else 0

    def add_export_bytes(self, tenant_id: str, day: str, byte_count: int) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO export_usage (tenant_id, day, export_bytes)
                VALUES (?,?,?)
                ON CONFLICT(tenant_id, day) DO UPDATE SET
                    export_bytes = export_usage.export_bytes + excluded.export_bytes
                """,
                (tenant_id, day, byte_count),
            )
            self._conn.commit()

    def prune_old_export_usage(self, *, keep_days: int = 400) -> None:
        """删除过久前的导出计数行，避免表无限增长（默认保留约一年多）。"""
        if keep_days < 30:
            return
        with self._lock:
            self._conn.execute(
                """
                DELETE FROM export_usage
                WHERE day < date('now', ?)
                """,
                (f"-{int(keep_days)} days",),
            )
            self._conn.commit()

    def migrate_legacy_users_from_json(self, users_json: Path) -> None:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM jwt_legacy_users").fetchone()
        if row and int(row["n"]) > 0:
            return
        if not users_json.is_file():
            return
        try:
            data = json.loads(users_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        rows = list(data) if isinstance(data, list) else []
        with self._lock:
            for r in rows:
                if not isinstance(r, dict):
                    continue
                u = str(r.get("username", "")).strip()
                if not u:
                    continue
                try:
                    self._conn.execute(
                        """
                        INSERT OR IGNORE INTO jwt_legacy_users (username, salt, hash)
                        VALUES (?,?,?)
                        """,
                        (u, str(r.get("salt", "")), str(r.get("hash", ""))),
                    )
                except sqlite3.Error:
                    continue
            self._conn.commit()

    def legacy_user_verify_row(self, username: str) -> tuple[str, str] | None:
        row = self._conn.execute(
            "SELECT salt, hash FROM jwt_legacy_users WHERE username=?",
            (username,),
        ).fetchone()
        if row is None:
            return None
        return (str(row["salt"]), str(row["hash"]))

    def legacy_insert_user(self, username: str, salt: str, hash_hex: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO jwt_legacy_users (username, salt, hash)
                VALUES (?,?,?)
                """,
                (username, salt, hash_hex),
            )
            self._conn.commit()

    def legacy_list_usernames(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT username FROM jwt_legacy_users ORDER BY username"
        ).fetchall()
        return [str(r["username"]) for r in rows]

    def ping(self) -> None:
        self._conn.execute("SELECT 1").fetchone()

    def is_login_locked(self, key_hash: str) -> bool:
        row = self._conn.execute(
            "SELECT locked_until FROM login_throttle WHERE login_key_hash=?",
            (key_hash,),
        ).fetchone()
        if row is None:
            return False
        return int(row["locked_until"]) > int(time.time())

    def record_login_failure(self, key_hash: str) -> None:
        now = int(time.time())
        window = int(os.environ.get("MASP_LOGIN_FAIL_WINDOW_SEC", "900"))
        max_fails = int(os.environ.get("MASP_LOGIN_MAX_FAILS", "8"))
        lock_sec = int(os.environ.get("MASP_LOGIN_LOCKOUT_SEC", "900"))
        with self._lock:
            row = self._conn.execute(
                """
                SELECT fail_count, window_start, locked_until FROM login_throttle
                WHERE login_key_hash=?
                """,
                (key_hash,),
            ).fetchone()
            if row is not None and int(row["locked_until"]) > now:
                self._conn.commit()
                return
            if row is None:
                self._conn.execute(
                    """
                    INSERT INTO login_throttle (login_key_hash, fail_count, window_start, locked_until)
                    VALUES (?,?,?,0)
                    """,
                    (key_hash, 1, now),
                )
            else:
                ws = int(row["window_start"])
                fc = int(row["fail_count"])
                lu = int(row["locked_until"])
                if now - ws > window:
                    fc = 1
                    ws = now
                else:
                    fc += 1
                if fc >= max_fails:
                    lu = now + lock_sec
                    fc = 0
                    ws = now
                self._conn.execute(
                    """
                    UPDATE login_throttle SET fail_count=?, window_start=?, locked_until=?
                    WHERE login_key_hash=?
                    """,
                    (fc, ws, lu, key_hash),
                )
            self._conn.commit()

    def record_login_success(self, key_hash: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM login_throttle WHERE login_key_hash=?",
                (key_hash,),
            )
            self._conn.commit()
