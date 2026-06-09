from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from mcp_agent_safe_protecter.api.tenant_registry import TenantTraceRegistry


class TenantRegistryCacheTests(unittest.TestCase):
    def tearDown(self) -> None:
        os.environ.pop("MASP_TRACE_STORE_CACHE_MAX", None)

    def test_cache_max_evicts_fifo(self) -> None:
        os.environ["MASP_TRACE_STORE_CACHE_MAX"] = "2"
        tmp = Path(tempfile.mkdtemp())
        reg = TenantTraceRegistry(tmp)
        try:
            reg.get_store("a")
            reg.get_store("b")
            self.assertEqual(reg.trace_store_cache_stats()["cached_count"], 2)
            reg.get_store("c")
            stats = reg.trace_store_cache_stats()
            self.assertEqual(stats["cached_count"], 2)
            self.assertEqual(set(stats["cached_tenant_ids"]), {"b", "c"})
            self.assertEqual(stats["cache_max"], 2)
        finally:
            reg.close_all()


if __name__ == "__main__":
    unittest.main()
