from __future__ import annotations

import json
import logging
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_LOG = logging.getLogger(__name__)


def _apply_kv(env_updates: dict[str, Any]) -> int:
    """仅当目标环境变量未设置或为空时写入（本地/Docker 显式 env 优先）。"""
    n = 0
    for key, raw in env_updates.items():
        k = str(key).strip()
        if not k:
            continue
        cur = os.environ.get(k)
        if cur is not None and str(cur).strip() != "":
            continue
        os.environ[k] = str(raw)
        n += 1
    return n


def _vault_ssl_context() -> ssl.SSLContext | None:
    if os.environ.get("MASP_VAULT_TLS_VERIFY", "1").strip() == "0":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


def load_from_vault_kv2() -> dict[str, Any]:
    """
    HashiCorp Vault KV v2：读取 ``MASP_VAULT_SECRET_PATH``（如 ``secret/data/masp``）。
    环境变量：``MASP_VAULT_ADDR``、``MASP_VAULT_TOKEN``。
    """
    addr = os.environ.get("MASP_VAULT_ADDR", "").strip().rstrip("/")
    token = os.environ.get("MASP_VAULT_TOKEN", "").strip()
    path = os.environ.get("MASP_VAULT_SECRET_PATH", "").strip().lstrip("/")
    if not (addr and token and path):
        raise ValueError("Vault 需要 MASP_VAULT_ADDR、MASP_VAULT_TOKEN、MASP_VAULT_SECRET_PATH")

    url = f"{addr}/v1/{path}"
    req = urllib.request.Request(url, headers={"X-Vault-Token": token})
    ctx = _vault_ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Vault HTTP {e.code}: {body}") from e

    data = payload.get("data", {}).get("data")
    if not isinstance(data, dict):
        raise RuntimeError("Vault 响应不是 KV v2 预期的 data.data 对象")
    return {str(k): v for k, v in data.items()}


def load_from_nacos_properties() -> dict[str, str]:
    """
    Nacos 配置（文本 properties）：``KEY=value`` 逐行解析。
    环境变量：``MASP_NACOS_SERVER``（如 ``http://nacos:8848``）、``MASP_NACOS_DATA_ID``、
    ``MASP_NACOS_GROUP``（默认 DEFAULT_GROUP）、可选 ``MASP_NACOS_NAMESPACE``（tenant）。
    """
    server = os.environ.get("MASP_NACOS_SERVER", "").strip().rstrip("/")
    data_id = os.environ.get("MASP_NACOS_DATA_ID", "").strip()
    group = os.environ.get("MASP_NACOS_GROUP", "DEFAULT_GROUP").strip()
    tenant = os.environ.get("MASP_NACOS_NAMESPACE", "").strip()

    if not (server and data_id):
        raise ValueError("Nacos 需要 MASP_NACOS_SERVER、MASP_NACOS_DATA_ID")

    q = urllib.parse.urlencode(
        {"dataId": data_id, "group": group, **({"tenant": tenant} if tenant else {})}
    )
    url = f"{server}/nacos/v1/cs/configs?{q}"
    req = urllib.request.Request(url)
    if os.environ.get("MASP_NACOS_TLS_VERIFY", "1").strip() == "0":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener_ctx = ctx
    else:
        opener_ctx = None

    try:
        with urllib.request.urlopen(req, timeout=30, context=opener_ctx) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Nacos HTTP {e.code}: {body}") from e

    out: dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("!"):
            continue
        if "=" not in s:
            continue
        k, v = s.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def bootstrap_external_config() -> None:
    """
    在 ``create_app`` / uvicorn 启动前调用。
    ``MASP_CONFIG_SOURCE``：``vault`` | ``nacos`` | 空（跳过）。
    """
    src = os.environ.get("MASP_CONFIG_SOURCE", "").strip().lower()
    if not src:
        return

    try:
        if src == "vault":
            data = load_from_vault_kv2()
            n = _apply_kv(data)
            _LOG.info("已从 Vault 合并 %s 个环境变量（仅填空项）", n)
        elif src == "nacos":
            data = load_from_nacos_properties()
            n = _apply_kv(data)
            _LOG.info("已从 Nacos 合并 %s 个环境变量（仅填空项）", n)
        else:
            _LOG.warning("未知的 MASP_CONFIG_SOURCE=%r，已忽略", src)
    except Exception:
        _LOG.exception("外部配置加载失败（MASP_CONFIG_SOURCE=%s）", src)
        try:
            from mcp_agent_safe_protecter.api.metrics_prom import (
                REMOTE_CONFIG_FETCH_FAILURES,
            )

            REMOTE_CONFIG_FETCH_FAILURES.inc()
        except Exception:
            pass
        if os.environ.get("MASP_CONFIG_STRICT", "").strip() == "1":
            raise
