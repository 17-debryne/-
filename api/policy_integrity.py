from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path


def verify_quotas_json_hmac_if_configured(json_path: Path) -> None:
    """
    若设置 ``MASP_POLICY_FILE_HMAC_SECRET``，则 ``tenant_quotas.json`` 必须存在同级
    ``tenant_quotas.json.hmac``（单行 hex 的 HMAC-SHA256(body, secret)）。

    校验失败或未提供签名文件时抛出 ``RuntimeError``（应在导入 SQLite 前调用）。
    未设置密钥则不校验。
    """
    secret = os.environ.get("MASP_POLICY_FILE_HMAC_SECRET", "").strip()
    if not secret:
        return
    if not json_path.is_file():
        return
    sig_path = json_path.with_name(json_path.name + ".hmac")
    if not sig_path.is_file():
        raise RuntimeError(
            f"已配置 MASP_POLICY_FILE_HMAC_SECRET，但缺少签名文件: {sig_path.name}"
        )
    body = json_path.read_bytes()
    expected = sig_path.read_text(encoding="utf-8").strip()
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        raise RuntimeError("tenant_quotas.json HMAC 校验失败，拒绝导入配额")


def compute_file_hmac_sha256_hex(body: bytes, secret: str) -> str:
    """生成 ``tenant_quotas.json.hmac`` 内容时可用。"""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
