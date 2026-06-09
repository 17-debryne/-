from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_agent_safe_protecter.branches.traceability import TraceabilityDetector
from mcp_agent_safe_protecter.core.types import ScanContext
from mcp_agent_safe_protecter.traceability.service import TraceabilityService
from mcp_agent_safe_protecter.traceability.store_sqlite import SQLiteTraceStore


class TraceabilityIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp())
        self.store = SQLiteTraceStore(self._tmp / "t.db")
        self.svc = TraceabilityService(self.store)
        self.det = TraceabilityDetector(store=self.store)

    def tearDown(self) -> None:
        self.store.close()

    def test_persist_verify_and_detect(self) -> None:
        sid = self.svc.open_trace("tenant-a", "agent-1", meta={"title": "acc-review"})
        self.svc.record_operation_hop(
            sid,
            {"step": "pay", "actor_type": "human", "principal_id": "u1", "op": "transfer"},
        )
        self.svc.record_data_mutation(
            sid,
            {
                "op": "update",
                "old_value": {"amt": 1},
                "new_value": {"amt": 2},
                "actor": "u1",
                "ts": "2026-05-08T12:00:00",
                "trigger": "ui",
                "reason": "fix typo",
            },
        )
        ok, msg = self.svc.verify_integrity(sid)
        self.assertTrue(ok, msg)

        ctx = self.svc.build_scan_context(sid)
        findings = self.det.analyze(ctx)
        cats = {f.category for f in findings}
        self.assertIn("trace_op_chain_summary", cats)
        self.assertIn("trace_crud_summary", cats)

    def test_overlay_over_store(self) -> None:
        sid = self.svc.open_trace("t", "a")
        self.svc.record_compliance_audit(sid, {"immutable_store": True})
        ctx = ScanContext(
            trace_session_id=sid,
            traceability={
                "session_id": sid,
                "compliance_audit": {"immutable_store": False},
            },
        )
        findings = self.det.analyze(ctx)
        self.assertTrue(any(f.category == "trace_compliance_mutable_log" for f in findings))

    def test_report_bundle(self) -> None:
        sid = self.svc.open_trace("t", "a")
        self.svc.record_error(sid, {"message": "x", "category": "code", "stack": "..."})
        rep = self.svc.generate_report(sid, redact_export=False)
        self.assertIn("integrity", rep)
        self.assertTrue(rep["integrity"]["chain_ok"])


if __name__ == "__main__":
    unittest.main()
