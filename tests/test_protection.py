from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from mcp_agent_safe_protecter.api.factory import create_app
from mcp_agent_safe_protecter.api.tenant_registry import TenantTraceRegistry


class ProtectionApiTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["MASP_API_KEY"] = "unit-test-key"
        self._tmp = Path(tempfile.mkdtemp())
        self.registry = TenantTraceRegistry(self._tmp)
        self.app = create_app(registry=self.registry)

    def tearDown(self) -> None:
        self.registry.close_all()

    def test_protection_evaluate_returns_signals(self) -> None:
        h = {"X-API-Key": "unit-test-key"}
        with TestClient(self.app) as client:
            r = client.post(
                "/api/v1/tenants/acme/sessions",
                json={"agent_id": "prot-agent"},
                headers=h,
            )
            sid = r.json()["session_id"]
            r2 = client.post(
                f"/api/v1/tenants/acme/sessions/{sid}/protection/evaluate",
                json={
                    "overlay": {
                        "attempted_action": {
                            "target": "admin_console",
                            "name": "open_admin",
                        },
                        "principal": {"role": "agent", "tenant_id": "acme"},
                        "rbac_policy": {"role_capabilities": {"agent": ["tool.run"]}},
                    }
                },
                headers=h,
            )
            self.assertEqual(r2.status_code, 200)
            data = r2.json()
            self.assertIn("signals", data)
            self.assertIn("summary", data)
            cats = {s["category"] for s in data["signals"]}
            self.assertIn("admin_access_deny", cats)

    def test_protection_invalid_branch(self) -> None:
        h = {"X-API-Key": "unit-test-key"}
        with TestClient(self.app) as client:
            r = client.post(
                "/api/v1/tenants/acme/sessions",
                json={"agent_id": "x"},
                headers=h,
            )
            sid = r.json()["session_id"]
            r2 = client.post(
                f"/api/v1/tenants/acme/sessions/{sid}/protection/evaluate",
                json={"overlay": {}, "enabled_branches": ["not_real"]},
                headers=h,
            )
            self.assertEqual(r2.status_code, 400)


if __name__ == "__main__":
    unittest.main()
