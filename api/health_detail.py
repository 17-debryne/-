from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from fastapi import Request


def _disk_free_ratio(path: Path) -> float | None:
    try:
        u = shutil.disk_usage(path)
        return u.free / max(u.total, 1)
    except OSError:
        return None


def health_checks(request: Request, *, base: Path) -> dict[str, Any]:
    """返回 ``checks`` 映射；值 ``ok`` 表示正常，其它为简短原因字符串。"""
    checks: dict[str, str] = {}

    app_db = getattr(request.app.state, "app_db", None)
    if app_db is not None:
        try:
            app_db.ping()
            checks["app_database"] = "ok"
        except Exception as e:
            checks["app_database"] = f"error:{type(e).__name__}"

    if getattr(request.app.state, "audit_store", None) is not None:
        checks["audit_database"] = "ok"

    ratio = _disk_free_ratio(base)
    if ratio is None:
        checks["data_dir_disk"] = "unknown"
    elif ratio < float(os.environ.get("MASP_HEALTH_MIN_DISK_FREE_RATIO", "0.02")):
        checks["data_dir_disk"] = f"low_space:{ratio:.4f}"
    else:
        checks["data_dir_disk"] = "ok"

    bad = [k for k, v in checks.items() if v != "ok"]
    status = "ok" if not bad else "degraded"
    if os.environ.get("MASP_HEALTH_STRICT", "").strip() == "1":
        critical = any(v.startswith("error:") for v in checks.values())
        if critical:
            status = "unhealthy"
    return {"checks": checks, "health_status": status}
