from __future__ import annotations

import os
from pathlib import Path


def resolve_audit_database_path(data_dir: str | Path) -> Path:
    """
    审计库路径。

    - ``MASP_AUDIT_DATABASE``：绝对路径或相对于 ``data_dir`` 的路径。
    - 默认：``{data_dir}/masp_audit.sqlite3``。
    """
    base = Path(data_dir)
    raw = os.environ.get("MASP_AUDIT_DATABASE", "").strip()
    if raw:
        p = Path(raw)
        return p if p.is_absolute() else base / p
    return base / "masp_audit.sqlite3"
