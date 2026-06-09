from __future__ import annotations

import hashlib
import hmac
import os
import tempfile
import time
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from mcp_agent_safe_protecter.api.factory import create_app
from mcp_agent_safe_protecter.api.policy_integrity import (
    compute_file_hmac_sha256_hex,
    verify_quotas_json_hmac_if_configured,
)
from mcp_agent_safe_protecter.api.tenant_registry import TenantTraceRegistry


class LoginLockoutTests(unittest.TestCase):
    def tearDown(self) -> None:
        for k in (
            "MASP_LOGIN_MAX_FAILS",
            "MASP_LOGIN_FAIL_WINDOW_SEC",
            "MASP_LOGIN_LOCKOUT_SEC",
            "MASP_BOOTSTRAP_ADMIN_PASSWORD",
            "MASP_API_KEY",
        ):
            os.environ.pop(k, None)

    def test_login_lockout_after_failed_attempts(self) -> None:
        os.environ["MASP_API_KEY"] = "k"
        os.environ["MASP_BOOTSTRAP_ADMIN_PASSWORD"] = "good-password-here"
        os.environ["MASP_LOGIN_MAX_FAILS"] = "3"
        os.environ["MASP_LOGIN_FAIL_WINDOW_SEC"] = "3600"
        tmp = Path(tempfile.mkdtemp())
        reg = TenantTraceRegistry(tmp)
        app = create_app(registry=reg)
        try:
            with TestClient(app) as client:
                for _ in range(3):
                    r = client.post(
                        "/api/v1/auth/login",
                        json={"login": "admin", "password": "wrong"},
                    )
                    self.assertEqual(r.status_code, 401)
                r4 = client.post(
                    "/api/v1/auth/login",
                    json={"login": "admin", "password": "wrong"},
                )
                self.assertEqual(r4.status_code, 429)
                r5 = client.post(
                    "/api/v1/auth/login",
                    json={"login": "admin", "password": "good-password-here"},
                )
                self.assertEqual(r5.status_code, 429)
        finally:
            reg.close_all()


class AdminAccessHmacOrApiKeyTests(unittest.TestCase):
    def tearDown(self) -> None:
        os.environ.pop("MASP_ADMIN_HMAC_SECRET", None)
        os.environ.pop("MASP_API_KEY", None)

    def test_admin_accepts_api_key_when_hmac_secret_configured(self) -> None:
        os.environ["MASP_ADMIN_HMAC_SECRET"] = "admin-hmac-secret"
        os.environ["MASP_API_KEY"] = "unit-key"
        tmp = Path(tempfile.mkdtemp())
        reg = TenantTraceRegistry(tmp)
        app = create_app(registry=reg)
        try:
            with TestClient(app) as client:
                r = client.get(
                    "/api/v1/admin/cache/stats",
                    headers={"X-API-Key": "unit-key"},
                )
                self.assertEqual(r.status_code, 200)
        finally:
            reg.close_all()

    def test_admin_accepts_hmac_without_api_key(self) -> None:
        secret = b"signing-secret"
        os.environ["MASP_ADMIN_HMAC_SECRET"] = secret.decode()
        tmp = Path(tempfile.mkdtemp())
        reg = TenantTraceRegistry(tmp)
        app = create_app(registry=reg)
        try:
            with TestClient(app) as client:
                path = "/api/v1/admin/cache/stats"
                ts = int(time.time())
                msg = f"{ts}\nGET\n{path}".encode("utf-8")
                sig = hmac.new(secret, msg, hashlib.sha256).hexdigest()
                r = client.get(
                    path,
                    headers={
                        "X-Masp-Timestamp": str(ts),
                        "X-Masp-Signature": sig,
                    },
                )
                self.assertEqual(r.status_code, 200)
        finally:
            reg.close_all()


class PolicyHmacTests(unittest.TestCase):
    def tearDown(self) -> None:
        os.environ.pop("MASP_POLICY_FILE_HMAC_SECRET", None)

    def test_verify_quotas_hmac_good_and_bad(self) -> None:
        secret = "unit-test-hmac-secret"
        os.environ["MASP_POLICY_FILE_HMAC_SECRET"] = secret
        tmp = Path(tempfile.mkdtemp())
        j = tmp / "tenant_quotas.json"
        body = b'{"default":{"max_sessions":1}}'
        j.write_bytes(body)
        sig = tmp / "tenant_quotas.json.hmac"
        sig.write_text("deadbeef")
        with self.assertRaises(RuntimeError):
            verify_quotas_json_hmac_if_configured(j)

        sig.write_text(compute_file_hmac_sha256_hex(body, secret))
        verify_quotas_json_hmac_if_configured(j)


if __name__ == "__main__":
    unittest.main()
