from __future__ import annotations

import os
import shutil
from pathlib import Path


def resolve_auth_database_path(data_dir: str | Path) -> Path:
    """
    认证库路径。

    - 环境变量 ``MASP_AUTH_DATABASE``：绝对路径，或相对于 ``data_dir`` 的相对路径。
    - 默认：``{data_dir}/masp_auth.sqlite3``（等价于常见约定 ``data/masp_auth.sqlite3`` 当数据目录为 ``data`` 时）。

    若目标文件尚不存在且存在旧库 ``{data_dir}/auth/identity.sqlite3``，则复制一份到新路径（便于平滑迁移）。
    """
    base = Path(data_dir)
    raw = os.environ.get("MASP_AUTH_DATABASE", "").strip()
    if raw:
        p = Path(raw)
        path = p if p.is_absolute() else (base / p)
    else:
        path = base / "masp_auth.sqlite3"

    legacy = base / "auth" / "identity.sqlite3"
    if not path.exists() and legacy.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(legacy, path)
    return path
