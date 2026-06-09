from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_agent_safe_protecter.identity.passwords import hash_password, verify_password

_LOG = logging.getLogger(__name__)

_USER_RE = re.compile(r"^[a-zA-Z0-9_\u4e00-\u9fff]{2,32}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(addr: str) -> bool:
    return bool(_EMAIL_RE.fullmatch(addr.strip()))


def _now_ts() -> int:
    return int(time.time())


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_phone(raw: str) -> str | None:
    s = raw.strip().replace(" ", "").replace("-", "")
    if s.startswith("+86"):
        s = s[3:]
    if s.isdigit() and len(s) == 11 and s.startswith("1"):
        return s
    return None


def hash_otp(code: str, address: str) -> str:
    pepper = os.environ.get("MASP_OTP_PEPPER", "masp-otp-pepper-change-me")
    blob = f"{pepper}|{address}|{code}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def hash_email_link_token(raw_token: str, email: str) -> str:
    """邮箱魔法链接一次性令牌（仅存哈希）。"""
    pepper = os.environ.get(
        "MASP_EMAIL_LINK_PEPPER",
        os.environ.get("MASP_OTP_PEPPER", "masp-otp-pepper-change-me"),
    )
    norm = email.strip().lower()
    blob = f"email-link-v1|{pepper}|{norm}|{raw_token}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _apply_auth_sqlite_max_size_mib(conn: sqlite3.Connection) -> None:
    raw = os.environ.get("MASP_AUTH_SQLITE_MAX_SIZE_MIB", "").strip()
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


@dataclass(slots=True)
class UserRecord:
    public_id: str
    id: str
    username: str
    email: str | None
    phone: str | None
    password_hash: str | None
    salt: str | None
    email_verified: bool
    phone_verified: bool


class IdentityStore:
    """
    认证库（默认路径见 ``identity.auth_paths.resolve_auth_database_path``）：
    ``users``、``oauth_accounts``、``email_verification_tokens``、``phone_otp_codes``、
    ``oauth_states``、``revoked_tokens``；WAL 已启用。
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
        _apply_auth_sqlite_max_size_mib(self._conn)

    @property
    def database_path(self) -> Path:
        return self._path

    def close(self) -> None:
        self._conn.close()

    def _ensure_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT UNIQUE,
                phone TEXT UNIQUE,
                password_hash TEXT,
                salt TEXT,
                display_name TEXT,
                created_at TEXT NOT NULL,
                email_verified INTEGER NOT NULL DEFAULT 0,
                phone_verified INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS oauth_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                provider TEXT NOT NULL,
                openid TEXT NOT NULL,
                unionid TEXT,
                raw_json TEXT,
                UNIQUE(provider, openid)
            );
            CREATE TABLE IF NOT EXISTS oauth_states (
                state TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                exp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_revoked_exp ON revoked_tokens(exp);
            CREATE TABLE IF NOT EXISTS email_verification_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                purpose TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_evt_email_purpose
                ON email_verification_tokens(email, purpose, consumed);
            CREATE TABLE IF NOT EXISTS phone_otp_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phone TEXT NOT NULL,
                purpose TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_pot_phone_purpose
                ON phone_otp_codes(phone, purpose, consumed);
            """
        )
        self._migrate_users_public_id()
        self._migrate_legacy_verifications_table()
        self._conn.commit()

    def _migrate_users_public_id(self) -> None:
        cols = {str(r[1]) for r in self._conn.execute("PRAGMA table_info(users)").fetchall()}
        if "public_id" not in cols:
            self._conn.execute("ALTER TABLE users ADD COLUMN public_id TEXT")
        self._conn.execute(
            """
            UPDATE users
            SET public_id = id
            WHERE public_id IS NULL OR TRIM(COALESCE(public_id, '')) = ''
            """
        )
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_public_id ON users(public_id)"
        )

    def _migrate_legacy_verifications_table(self) -> None:
        row = self._conn.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type='table' AND name='verifications'
            """
        ).fetchone()
        if row is None:
            return
        legacy = self._conn.execute(
            "SELECT channel, address, code_hash, purpose, expires_at, consumed FROM verifications"
        ).fetchall()
        now = _now_ts()
        for r in legacy:
            created = now
            ch = str(r["channel"])
            addr = str(r["address"])
            if ch == "email":
                self._conn.execute(
                    """
                    INSERT INTO email_verification_tokens
                        (email, purpose, token_hash, expires_at, consumed, created_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (
                        addr,
                        str(r["purpose"]),
                        str(r["code_hash"]),
                        int(r["expires_at"]),
                        int(r["consumed"]),
                        created,
                    ),
                )
            elif ch == "phone":
                self._conn.execute(
                    """
                    INSERT INTO phone_otp_codes
                        (phone, purpose, token_hash, expires_at, consumed, created_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (
                        addr,
                        str(r["purpose"]),
                        str(r["code_hash"]),
                        int(r["expires_at"]),
                        int(r["consumed"]),
                        created,
                    ),
                )
        self._conn.execute("DROP TABLE IF EXISTS verifications")

    def count_users(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        return int(row["n"]) if row else 0

    def ensure_bootstrap_admin(self) -> None:
        if self.count_users() > 0:
            return
        pw = os.environ.get("MASP_BOOTSTRAP_ADMIN_PASSWORD", "").strip()
        if not pw:
            return
        salt, phash = hash_password(pw)
        uid = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO users (
                    id, public_id, username, email, phone,
                    password_hash, salt, display_name, created_at, email_verified, phone_verified
                )
                VALUES (?, ?, ?, NULL, NULL, ?, ?, 'admin', ?, 1, 0)
                """,
                (uid, uid, "admin", phash, salt, _utc_iso()),
            )
            self._conn.commit()
        _LOG.info("已初始化 IdentityStore 内置管理员 admin")

    def _row_to_user(self, row: sqlite3.Row) -> UserRecord:
        pid = row["public_id"] if row["public_id"] else row["id"]
        return UserRecord(
            public_id=str(pid),
            id=row["id"],
            username=row["username"],
            email=row["email"],
            phone=row["phone"],
            password_hash=row["password_hash"],
            salt=row["salt"],
            email_verified=bool(row["email_verified"]),
            phone_verified=bool(row["phone_verified"]),
        )

    def find_user_by_login(self, login: str) -> UserRecord | None:
        raw = login.strip()
        if not raw:
            return None
        row = None
        if "@" in raw:
            row = self._conn.execute(
                "SELECT * FROM users WHERE lower(email) = lower(?)",
                (raw,),
            ).fetchone()
        else:
            norm = normalize_phone(raw)
            if norm:
                row = self._conn.execute(
                    "SELECT * FROM users WHERE phone = ?", (norm,)
                ).fetchone()
            if row is None:
                row = self._conn.execute(
                    "SELECT * FROM users WHERE username = ?", (raw,)
                ).fetchone()
        if row is None:
            return None
        return self._row_to_user(row)

    def verify_password_login(self, login: str, password: str) -> str | None:
        u = self.find_user_by_login(login)
        if not u or not u.password_hash or not u.salt:
            return None
        if verify_password(password, u.salt, u.password_hash):
            return u.username
        return None

    def create_user_with_password(
        self,
        *,
        username: str,
        email: str | None,
        phone: str | None,
        password: str,
        email_verified: bool,
        phone_verified: bool,
    ) -> str:
        if not _USER_RE.fullmatch(username):
            raise ValueError("用户名 2–32 位，含字母数字下划线或中文")
        salt, phash = hash_password(password)
        uid = str(uuid.uuid4())
        with self._lock:
            try:
                self._conn.execute(
                    """
                    INSERT INTO users (
                        id, public_id, username, email, phone,
                        password_hash, salt, display_name, created_at, email_verified, phone_verified
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        uid,
                        uid,
                        username,
                        email,
                        phone,
                        phash,
                        salt,
                        username,
                        _utc_iso(),
                        int(email_verified),
                        int(phone_verified),
                    ),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as e:
                raise ValueError("用户名、邮箱或手机号已存在") from e
        return uid

    def save_verification(
        self, channel: str, address: str, code: str, purpose: str, ttl_sec: int
    ) -> None:
        exp = _now_ts() + ttl_sec
        th = hash_otp(code, address)
        created = _now_ts()
        with self._lock:
            if channel == "email":
                self._conn.execute(
                    """
                    INSERT INTO email_verification_tokens
                        (email, purpose, token_hash, expires_at, consumed, created_at)
                    VALUES (?,?,?,?,0,?)
                    """,
                    (address, purpose, th, exp, created),
                )
            elif channel == "phone":
                self._conn.execute(
                    """
                    INSERT INTO phone_otp_codes
                        (phone, purpose, token_hash, expires_at, consumed, created_at)
                    VALUES (?,?,?,?,0,?)
                    """,
                    (address, purpose, th, exp, created),
                )
            else:
                raise ValueError(f"未知 channel: {channel}")
            self._conn.commit()

    def consume_verification(
        self, channel: str, address: str, code: str, purpose: str
    ) -> bool:
        th = hash_otp(code, address)
        now = _now_ts()
        with self._lock:
            if channel == "email":
                row = self._conn.execute(
                    """
                    SELECT id FROM email_verification_tokens
                    WHERE email=? AND purpose=? AND consumed=0 AND expires_at>?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (address, purpose, now),
                ).fetchone()
                tbl = "email_verification_tokens"
            elif channel == "phone":
                row = self._conn.execute(
                    """
                    SELECT id FROM phone_otp_codes
                    WHERE phone=? AND purpose=? AND consumed=0 AND expires_at>?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (address, purpose, now),
                ).fetchone()
                tbl = "phone_otp_codes"
            else:
                return False
            if row is None:
                return False
            rid = int(row["id"])
            chk = self._conn.execute(
                f"SELECT token_hash FROM {tbl} WHERE id=?", (rid,)
            ).fetchone()
            if not chk or chk["token_hash"] != th:
                return False
            self._conn.execute(f"UPDATE {tbl} SET consumed=1 WHERE id=?", (rid,))
            self._conn.commit()
        return True

    def save_email_verification_link(self, email: str, purpose: str, ttl_sec: int) -> str:
        """写入 ``email_verification_tokens``，返回明文链接令牌（仅用于邮件 URL）。"""
        addr = email.strip().lower()
        raw = secrets.token_urlsafe(32)
        exp = _now_ts() + ttl_sec
        th = hash_email_link_token(raw, addr)
        created = _now_ts()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO email_verification_tokens
                    (email, purpose, token_hash, expires_at, consumed, created_at)
                VALUES (?,?,?,?,0,?)
                """,
                (addr, purpose, th, exp, created),
            )
            self._conn.commit()
        return raw

    def verify_email_link_token(
        self,
        email: str,
        raw_token: str,
        purpose: str,
        *,
        consume: bool,
    ) -> bool:
        """校验魔法链接；``consume=True`` 时在成功校验后标记已消费。"""
        addr = email.strip().lower()
        th = hash_email_link_token(raw_token.strip(), addr)
        now = _now_ts()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, token_hash FROM email_verification_tokens
                WHERE email=? AND purpose=? AND consumed=0 AND expires_at>?
                ORDER BY id DESC LIMIT 1
                """,
                (addr, purpose, now),
            ).fetchone()
            if row is None or row["token_hash"] != th:
                return False
            if consume:
                self._conn.execute(
                    "UPDATE email_verification_tokens SET consumed=1 WHERE id=?",
                    (int(row["id"]),),
                )
                self._conn.commit()
        return True

    def oauth_save_state(self, provider: str, state: str, ttl_sec: int = 600) -> None:
        exp = _now_ts() + ttl_sec
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO oauth_states (state, provider, expires_at) VALUES (?,?,?)",
                (state, provider, exp),
            )
            self._conn.commit()

    def oauth_take_state(self, state: str, provider: str) -> bool:
        now = _now_ts()
        with self._lock:
            row = self._conn.execute(
                "SELECT provider, expires_at FROM oauth_states WHERE state=?",
                (state,),
            ).fetchone()
            if row is None or row["provider"] != provider or row["expires_at"] < now:
                return False
            self._conn.execute("DELETE FROM oauth_states WHERE state=?", (state,))
            self._conn.commit()
        return True

    def oauth_find_user(self, provider: str, openid: str) -> str | None:
        row = self._conn.execute(
            """
            SELECT u.username FROM oauth_accounts o JOIN users u ON u.id = o.user_id
            WHERE o.provider=? AND o.openid=?
            """,
            (provider, openid),
        ).fetchone()
        return str(row["username"]) if row else None

    def oauth_bind_or_register(
        self,
        provider: str,
        openid: str,
        unionid: str | None,
        display_name: str | None,
        raw: dict[str, Any],
    ) -> str:
        existing = self.oauth_find_user(provider, openid)
        if existing:
            return existing
        base = re.sub(r"[^a-zA-Z0-9_]", "_", (display_name or f"{provider}_{openid[:8]}"))
        base = base[:20] or f"{provider}_user"
        username = self.allocate_username(base)
        uid = str(uuid.uuid4())
        raw_json = json.dumps(raw, ensure_ascii=False)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO users (
                    id, public_id, username, email, phone,
                    password_hash, salt, display_name, created_at, email_verified, phone_verified
                )
                VALUES (?, ?, ?, NULL, NULL, NULL, NULL, ?, ?, 0, 0)
                """,
                (uid, uid, username, display_name or username, _utc_iso()),
            )
            self._conn.execute(
                """
                INSERT INTO oauth_accounts (user_id, provider, openid, unionid, raw_json)
                VALUES (?,?,?,?,?)
                """,
                (uid, provider, openid, unionid, raw_json),
            )
            self._conn.commit()
        return username

    def allocate_username(self, base: str) -> str:
        with self._lock:
            for i in range(0, 50):
                cand = base if i == 0 else f"{base}_{i}"
                row = self._conn.execute(
                    "SELECT 1 FROM users WHERE username=?", (cand,)
                ).fetchone()
                if row is None:
                    return cand
        raise RuntimeError("无法分配用户名")

    def revoke_token(self, jti: str, exp: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO revoked_tokens (jti, exp) VALUES (?, ?)",
                (jti, exp),
            )
            self._conn.commit()

    def is_token_revoked(self, jti: str) -> bool:
        self.prune_revoked()
        row = self._conn.execute(
            "SELECT 1 FROM revoked_tokens WHERE jti=?", (jti,)
        ).fetchone()
        return row is not None

    def prune_revoked(self) -> None:
        now = _now_ts()
        with self._lock:
            self._conn.execute("DELETE FROM revoked_tokens WHERE exp < ?", (now,))
            self._conn.commit()

    def prune_ephemeral(self) -> None:
        """删除已过期的邮箱验证码记录、短信 OTP、OAuth state。"""
        now = _now_ts()
        with self._lock:
            self._conn.execute(
                "DELETE FROM email_verification_tokens WHERE expires_at < ?", (now,)
            )
            self._conn.execute("DELETE FROM phone_otp_codes WHERE expires_at < ?", (now,))
            self._conn.execute("DELETE FROM oauth_states WHERE expires_at < ?", (now,))
            self._conn.commit()

    def prune_auth_database(self) -> None:
        """
        供 ``masp auth prune`` 调用：过期清理 + 可选按行数上限裁剪临时表。

        环境变量（可选）::

            MASP_AUTH_EMAIL_TOKEN_ROW_CAP   默认 50000
            MASP_AUTH_PHONE_OTP_ROW_CAP     默认 50000
            MASP_AUTH_OAUTH_STATE_ROW_CAP   默认 10000
            MASP_AUTH_REVOKED_ROW_CAP       默认 100000
        """
        self.prune_ephemeral()
        self.prune_revoked()
        self._cap_rows_pk(
            "email_verification_tokens",
            "MASP_AUTH_EMAIL_TOKEN_ROW_CAP",
            50_000,
        )
        self._cap_rows_pk(
            "phone_otp_codes",
            "MASP_AUTH_PHONE_OTP_ROW_CAP",
            50_000,
        )
        self._cap_oauth_states()
        self._cap_revoked_tokens()

    def _cap_rows_pk(self, table: str, env_key: str, default: int) -> None:
        raw = os.environ.get(env_key, "").strip()
        try:
            lim = int(raw) if raw else default
        except ValueError:
            lim = default
        if lim <= 0:
            return
        with self._lock:
            row = self._conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
            n = int(row["n"]) if row else 0
            excess = n - lim
            if excess <= 0:
                return
            self._conn.execute(
                f"""
                DELETE FROM {table} WHERE id IN (
                    SELECT id FROM {table} ORDER BY id ASC LIMIT ?
                )
                """,
                (excess,),
            )
            self._conn.commit()

    def _cap_oauth_states(self) -> None:
        raw = os.environ.get("MASP_AUTH_OAUTH_STATE_ROW_CAP", "").strip()
        try:
            lim = int(raw) if raw else 10_000
        except ValueError:
            lim = 10_000
        if lim <= 0:
            return
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM oauth_states").fetchone()
            n = int(row["n"]) if row else 0
            excess = n - lim
            if excess <= 0:
                return
            self._conn.execute(
                """
                DELETE FROM oauth_states WHERE state IN (
                    SELECT state FROM oauth_states ORDER BY expires_at ASC LIMIT ?
                )
                """,
                (excess,),
            )
            self._conn.commit()

    def _cap_revoked_tokens(self) -> None:
        raw = os.environ.get("MASP_AUTH_REVOKED_ROW_CAP", "").strip()
        try:
            lim = int(raw) if raw else 100_000
        except ValueError:
            lim = 100_000
        if lim <= 0:
            return
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM revoked_tokens").fetchone()
            n = int(row["n"]) if row else 0
            excess = n - lim
            if excess <= 0:
                return
            self._conn.execute(
                """
                DELETE FROM revoked_tokens WHERE jti IN (
                    SELECT jti FROM revoked_tokens ORDER BY exp ASC LIMIT ?
                )
                """,
                (excess,),
            )
            self._conn.commit()
