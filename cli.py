from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def _data_dir() -> Path:
    return Path(os.environ.get("MASP_DATA_DIR", "./var/masp"))


def cmd_auth_prune(_args: argparse.Namespace) -> None:
    from mcp_agent_safe_protecter.identity.auth_paths import resolve_auth_database_path
    from mcp_agent_safe_protecter.identity.store import IdentityStore

    p = resolve_auth_database_path(_data_dir())
    store = IdentityStore(p)
    try:
        store.prune_auth_database()
    finally:
        store.close()


def cmd_cache_clear(args: argparse.Namespace) -> None:
    from mcp_agent_safe_protecter.api.tenant_registry import TenantTraceRegistry

    reg = TenantTraceRegistry(_data_dir())
    try:
        tids: list[str] | None = args.tenants
        if tids is not None and len(tids) == 0:
            tids = None
        out = reg.evict_trace_store_cache(
            tids,
            checkpoint_wal=not args.no_checkpoint,
        )
        print(json.dumps(out, ensure_ascii=False, indent=2))
    finally:
        reg.close_all()


def cmd_query(args: argparse.Namespace) -> None:
    from mcp_agent_safe_protecter.audit.paths import resolve_audit_database_path
    from mcp_agent_safe_protecter.audit.store import AuditSQLiteStore

    p = resolve_audit_database_path(_data_dir())
    if not p.is_file():
        print(
            json.dumps(
                {"error": "audit database not found", "path": str(p.resolve())},
                ensure_ascii=False,
            )
        )
        return
    store = AuditSQLiteStore(p)
    try:
        rows = store.list_recent_evaluations(limit=args.limit)
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    finally:
        store.close()


def main() -> None:
    parser = argparse.ArgumentParser(prog="masp")
    sub = parser.add_subparsers(dest="cmd", required=True)

    auth = sub.add_parser("auth", help="认证库维护")
    auth_sub = auth.add_subparsers(dest="auth_cmd", required=True)
    p_prune = auth_sub.add_parser(
        "prune",
        help="清理过期邮箱/短信 OTP、OAuth state、JWT 吊销并按行数上限裁剪",
    )
    p_prune.set_defaults(func=cmd_auth_prune)

    cache = sub.add_parser("cache", help="服务端内存缓存维护")
    cache_sub = cache.add_subparsers(dest="cache_cmd", required=True)
    p_clear = cache_sub.add_parser(
        "clear",
        help="驱逐租户溯源 SQLite 连接缓存（可选 WAL checkpoint）",
    )
    p_clear.add_argument(
        "--tenant",
        action="append",
        dest="tenants",
        default=None,
        metavar="TENANT_ID",
        help="仅驱逐指定租户（可重复）；省略则驱逐全部已缓存连接",
    )
    p_clear.add_argument(
        "--no-checkpoint",
        action="store_true",
        help="跳过 PRAGMA wal_checkpoint",
    )
    p_clear.set_defaults(func=cmd_cache_clear)

    q = sub.add_parser("query", help="列出审计库最近评估会话")
    q.add_argument("--limit", type=int, default=20)
    q.set_defaults(func=cmd_query)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
