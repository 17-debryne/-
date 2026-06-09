from __future__ import annotations

from dataclasses import dataclass

from mcp_agent_safe_protecter.core.types import ScanContext


@dataclass(slots=True)
class ProtectionEvaluationContext:
    """
    防护评估输入：与 ``ScanContext`` 对齐，由采集端/网关注入结构化字段。
    各防护分支只读 ``scan``，产出 ``ProtectionSignal``。
    """

    scan: ScanContext

    @classmethod
    def from_scan(cls, scan: ScanContext) -> ProtectionEvaluationContext:
        return cls(scan=scan)
