from __future__ import annotations

import os
from pathlib import Path

from mcp_agent_safe_protecter.api.app_database import AppDatabase
from mcp_agent_safe_protecter.identity.passwords import hash_password, verify_password


class UserStore:
    """
    兼容旧版 JWT 登录：口令存放在 ``masp_app.sqlite3`` 的 ``jwt_legacy_users`` 表。

    首次会从 ``auth/users.json`` 迁移一行或多行至数据库，避免 JSON 无限增大。
    """

    def __init__(self, auth_dir: Path, app_db: AppDatabase) -> None:
        self._auth_dir = Path(auth_dir)
        self._auth_dir.mkdir(parents=True, exist_ok=True)
        self._users_path = self._auth_dir / "users.json"
        self._db = app_db
        self._db.migrate_legacy_users_from_json(self._users_path)

    def ensure_bootstrap(self) -> None:
        """若无用户且环境变量 ``MASP_BOOTSTRAP_ADMIN_PASSWORD`` 存在，则创建 admin。"""
        if self._db.legacy_list_usernames():
            return
        pw = os.environ.get("MASP_BOOTSTRAP_ADMIN_PASSWORD", "").strip()
        if not pw:
            return
        salt, phash = hash_password(pw)
        self._db.legacy_insert_user("admin", salt, phash)

    def verify(self, username: str, password: str) -> bool:
        self.ensure_bootstrap()
        row = self._db.legacy_user_verify_row(username)
        if row is None:
            return False
        salt, hash_hex = row
        return verify_password(password, salt, hash_hex)

    def list_usernames(self) -> list[str]:
        self.ensure_bootstrap()
        return self._db.legacy_list_usernames()
