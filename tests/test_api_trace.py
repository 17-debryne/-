from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from mcp_agent_safe_protecter.api.factory import create_app
from mcp_agent_safe_protecter.api.tenant_registry import TenantTraceRegistry


class ApiTraceTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["MASP_API_KEY"] = "unit-test-key"
        os.environ.pop("MASP_BOOTSTRAP_ADMIN_PASSWORD", None)
        self._tmp = Path(tempfile.mkdtemp())
        self.registry = TenantTraceRegistry(self._tmp)
        self.app = create_app(registry=self.registry)

    def tearDown(self) -> None:
        self.registry.close_all()

    def test_meta_requires_auth(self) -> None:
        with TestClient(self.app) as client:
            r = client.get("/api/v1/meta")
            self.assertEqual(r.status_code, 401)

    def test_session_event_report_flow(self) -> None:
        h = {"X-API-Key": "unit-test-key"}
        with TestClient(self.app) as client:
            r = client.post(
                "/api/v1/tenants/acme/sessions",
                json={"agent_id": "ag-1", "meta": {"title": "api-test"}},
                headers=h,
            )
            self.assertEqual(r.status_code, 200)
            sid = r.json()["session_id"]

            r2 = client.post(
                f"/api/v1/tenants/acme/sessions/{sid}/events",
                json={
                    "event_type": "operation_hop",
                    "payload": {
                        "step": "login",
                        "actor_type": "human",
                        "principal_id": "u1",
                        "op": "sso",
                    },
                },
                headers=h,
            )
            self.assertEqual(r2.status_code, 200)

            r3 = client.get(
                f"/api/v1/tenants/acme/sessions/{sid}/view",
                headers=h,
            )
            self.assertEqual(r3.status_code, 200)
            self.assertIn("traceability", r3.json())

            r4 = client.get(
                f"/api/v1/tenants/acme/sessions/{sid}/integrity",
                headers=h,
            )
            self.assertEqual(r4.status_code, 200)
            self.assertTrue(r4.json().get("chain_ok"))

            r5 = client.get(
                f"/api/v1/tenants/acme/sessions/{sid}/report?redact=false",
                headers=h,
            )
            self.assertEqual(r5.status_code, 200)
            self.assertIn("digest", r5.json())

    def test_export_file_writes_disk(self) -> None:
        h = {"X-API-Key": "unit-test-key"}
        with TestClient(self.app) as client:
            r = client.post(
                "/api/v1/tenants/acme/sessions",
                json={"agent_id": "ex"},
                headers=h,
            )
            sid = r.json()["session_id"]
            r2 = client.post(
                f"/api/v1/tenants/acme/sessions/{sid}/export/file",
                json={"redact": False},
                headers=h,
            )
            self.assertEqual(r2.status_code, 200)
            fn = r2.json()["filename"]
            path = self._tmp / "exports" / "acme" / fn
            self.assertTrue(path.is_file())

    def test_jwt_login_and_meta(self) -> None:
        os.environ["MASP_BOOTSTRAP_ADMIN_PASSWORD"] = "jwt-bootstrap-secret"
        tmp = Path(tempfile.mkdtemp())
        reg = TenantTraceRegistry(tmp)
        app = create_app(registry=reg)
        try:
            with TestClient(app) as client:
                r = client.post(
                    "/api/v1/auth/login",
                    json={"login": "admin", "password": "jwt-bootstrap-secret"},
                )
                self.assertEqual(r.status_code, 200)
                tok = r.json()["access_token"]
                self.assertTrue(tok)
                r2 = client.get(
                    "/api/v1/meta",
                    headers={"Authorization": f"Bearer {tok}"},
                )
                self.assertEqual(r2.status_code, 200)
                meta = r2.json()
                self.assertIn("app_database", meta)
                self.assertTrue(meta.get("app_database"))
                self.assertIn("auth_database", meta)
                self.assertIn("masp_auth.sqlite3", meta.get("auth_database", ""))
                self.assertIn("audit_database", meta)
                self.assertIn("masp_audit.sqlite3", meta.get("audit_database", ""))
                r3 = client.get(
                    "/api/v1/auth/me",
                    headers={"Authorization": f"Bearer {tok}"},
                )
                self.assertEqual(r3.json().get("subject"), "admin")
        finally:
            reg.close_all()

    def test_quota_blocks_second_session(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        (tmp / "tenant_quotas.json").write_text(
            json.dumps({"default": {"max_sessions": 1}}),
            encoding="utf-8",
        )
        reg = TenantTraceRegistry(tmp)
        app = create_app(registry=reg)
        h = {"X-API-Key": "unit-test-key"}
        try:
            with TestClient(app) as client:
                r1 = client.post(
                    "/api/v1/tenants/acme/sessions",
                    json={"agent_id": "a"},
                    headers=h,
                )
                self.assertEqual(r1.status_code, 200)
                r2 = client.post(
                    "/api/v1/tenants/acme/sessions",
                    json={"agent_id": "b"},
                    headers=h,
                )
                self.assertEqual(r2.status_code, 429)
        finally:
            reg.close_all()

    def test_scan_persists_audit_database(self) -> None:
        h = {"X-API-Key": "unit-test-key"}
        audit_path = self._tmp / "masp_audit.sqlite3"
        self.assertFalse(audit_path.exists())
        with TestClient(self.app) as client:
            r = client.post(
                "/api/v1/tenants/acme/sessions",
                json={"agent_id": "audit-agent"},
                headers=h,
            )
            self.assertEqual(r.status_code, 200)
            sid = r.json()["session_id"]
            r2 = client.post(
                f"/api/v1/tenants/acme/sessions/{sid}/scan",
                json={"overlay": {}},
                headers=h,
            )
            self.assertEqual(r2.status_code, 200)
        self.assertTrue(audit_path.is_file())
        from mcp_agent_safe_protecter.audit.store import AuditSQLiteStore

        au = AuditSQLiteStore(audit_path)
        try:
            rows = au.list_recent_evaluations(limit=5)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["trace_session_id"], sid)
            self.assertEqual(rows[0]["tenant_id"], "acme")
        finally:
            au.close()

    def test_append_event_rejects_oversized_payload(self) -> None:
        os.environ["MASP_MAX_EVENT_PAYLOAD_BYTES"] = "64"
        tmp = Path(tempfile.mkdtemp())
        reg = TenantTraceRegistry(tmp)
        app = create_app(registry=reg)
        h = {"X-API-Key": "unit-test-key"}
        try:
            with TestClient(app) as client:
                r = client.post(
                    "/api/v1/tenants/acme/sessions",
                    json={"agent_id": "a"},
                    headers=h,
                )
                sid = r.json()["session_id"]
                r2 = client.post(
                    f"/api/v1/tenants/acme/sessions/{sid}/events",
                    json={
                        "event_type": "operation_hop",
                        "payload": {"x": "y" * 200},
                    },
                    headers=h,
                )
                self.assertEqual(r2.status_code, 400)
        finally:
            reg.close_all()
            os.environ.pop("MASP_MAX_EVENT_PAYLOAD_BYTES", None)

    def test_admin_cache_stats_and_cleanup(self) -> None:
        h = {"X-API-Key": "unit-test-key"}
        with TestClient(self.app) as client:
            r0 = client.post(
                "/api/v1/tenants/acme/sessions",
                json={"agent_id": "cache-test"},
                headers=h,
            )
            self.assertEqual(r0.status_code, 200)
            r = client.get("/api/v1/admin/cache/stats", headers=h)
            self.assertEqual(r.status_code, 200)
            self.assertGreaterEqual(r.json()["components"][0]["cached_count"], 1)
            r2 = client.post(
                "/api/v1/admin/cache/cleanup",
                headers=h,
                json={
                    "tenant_ids": ["acme"],
                    "scopes": ["trace_stores"],
                    "checkpoint_wal": True,
                },
            )
            self.assertEqual(r2.status_code, 200)
            body = r2.json()
            self.assertTrue(body.get("ok"))
            self.assertIn("acme", body["results"][0]["evicted_tenant_ids"])
            r3 = client.get("/api/v1/admin/cache/stats", headers=h)
            self.assertEqual(r3.json()["components"][0]["cached_count"], 0)

    def test_invalid_tenant(self) -> None:
        h = {"X-API-Key": "unit-test-key"}
        bad = "x" * 65
        with TestClient(self.app) as client:
            r = client.post(
                f"/api/v1/tenants/{bad}/sessions",
                json={"agent_id": "x"},
                headers=h,
            )
            self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
