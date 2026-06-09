"""溯源子系统：SQLite 持久化、事件追加、完整性校验、检索与报告。"""

from mcp_agent_safe_protecter.traceability.export_preview import preview_export_audit_report
from mcp_agent_safe_protecter.traceability.models import (
    DamageKind,
    ErrorTraceCategory,
    StoredTraceEvent,
    ThreatTraceKind,
    TraceEventType,
    TraceLevel,
    TraceSession,
)
from mcp_agent_safe_protecter.traceability.search import (
    filter_incidents_by_conditions,
    fuzzy_match_incidents,
)
from mcp_agent_safe_protecter.traceability.service import TraceabilityService
from mcp_agent_safe_protecter.traceability.store_sqlite import SQLiteTraceStore
from mcp_agent_safe_protecter.traceability.util import (
    assign_trace_level,
    compute_audit_digest,
    merge_traceability_payload,
)

__all__ = [
    "SQLiteTraceStore",
    "TraceabilityService",
    "TraceSession",
    "StoredTraceEvent",
    "TraceEventType",
    "TraceLevel",
    "DamageKind",
    "ErrorTraceCategory",
    "ThreatTraceKind",
    "compute_audit_digest",
    "merge_traceability_payload",
    "assign_trace_level",
    "fuzzy_match_incidents",
    "filter_incidents_by_conditions",
    "preview_export_audit_report",
]
