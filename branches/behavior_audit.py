from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Sequence

from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity


class BehaviorAuditDetector:
    """
    分支六：行为审计与异常行为检测。
    全行为留痕校验 + 相对日常基线的偏离（深夜、批量敏感导出、高危地址）。
    """

    def __init__(self, *, night_hour_start: int = 23, night_hour_end: int = 6) -> None:
        self.night_start = night_hour_start
        self.night_end = night_hour_end

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        required = {
            str(x) for x in (ctx.session_info.get("behavior_required_kinds") or []) if x
        }
        if required:
            present = {str(e.get("kind")) for e in ctx.behavior_events}
            for rk in sorted(required - present):
                findings.append(
                    Finding(
                        BranchId.BEHAVIOR_AUDIT,
                        "missing_behavior_trace",
                        "全行为留痕缺失（相对策略要求的 kind）",
                        rk,
                        Severity.MEDIUM,
                        {"required_kind": rk},
                    )
                )

        if not ctx.behavior_events:
            return findings

        kinds = Counter(str(e.get("kind")) for e in ctx.behavior_events)
        if kinds:
            findings.append(
                Finding(
                    BranchId.BEHAVIOR_AUDIT,
                    "behavior_trace_summary",
                    "行为留痕聚合（审计摘要）",
                    ", ".join(f"{k}:{v}" for k, v in kinds.most_common(8)),
                    Severity.INFO,
                    dict(kinds),
                )
            )

        for e in ctx.behavior_events:
            ts = e.get("ts")
            if isinstance(ts, str):
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except ValueError:
                    dt = ctx.now
            elif isinstance(ts, datetime):
                dt = ts
            else:
                dt = ctx.now
            if self._is_night(dt):
                findings.append(
                    Finding(
                        BranchId.BEHAVIOR_AUDIT,
                        "off_hours_activity",
                        "深夜异常活动",
                        str(e.get("kind")),
                        Severity.LOW,
                        dict(e),
                    )
                )
            if e.get("kind") == "data_export" and int(e.get("row_count") or 0) > int(
                e.get("export_threshold", 10000)
            ):
                findings.append(
                    Finding(
                        BranchId.BEHAVIOR_AUDIT,
                        "bulk_sensitive_export",
                        "批量敏感数据导出行为",
                        str(e.get("target")),
                        Severity.HIGH,
                        dict(e),
                    )
                )

            dest = str(e.get("network_dest") or "")
            if dest and self._is_high_risk_host(dest, ctx):
                findings.append(
                    Finding(
                        BranchId.BEHAVIOR_AUDIT,
                        "high_risk_destination",
                        "频繁/异常访问高危地址",
                        dest,
                        Severity.MEDIUM,
                        dict(e),
                    )
                )

        return findings

    def _is_night(self, dt: datetime) -> bool:
        h = dt.hour
        if self.night_start <= self.night_end:
            return self.night_start <= h < self.night_end
        return h >= self.night_start or h < self.night_end

    @staticmethod
    def _is_high_risk_host(dest: str, ctx: ScanContext) -> bool:
        risky = set(ctx.environment_profile.get("high_risk_hosts") or ())
        return dest in risky
