from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class TraceLevel(int, Enum):
    """溯源等级（第四级最高）。"""

    L1 = 1
    L2 = 2
    L3 = 3
    L4 = 4


class ErrorTraceCategory(str, Enum):
    SYSTEM = "system"
    BUSINESS = "business"
    CODE = "code"
    CONFIG = "config"


class ThreatTraceKind(str, Enum):
    EXTERNAL_ATTACK = "external_attack"
    INTERNAL_PRIVILEGE_ABUSE = "internal_privilege_abuse"
    MALICIOUS_OPERATION = "malicious_operation"
    MALWARE = "malware"


class DamageKind(str, Enum):
    HARDWARE = "hardware"
    SOFTWARE = "software"
    LINK = "link"
    HUMAN = "human"


class TraceEventType(str, Enum):
    """追加写入存储的事件类型（用于还原八维溯源视图）。"""

    OPERATION_CHAIN_META = "operation_chain_meta"
    OPERATION_HOP = "operation_hop"
    FLOW_CHAIN_META = "flow_chain_meta"
    FLOW_STAGE = "flow_stage"
    DATA_MUTATION = "data_mutation"
    ASSET_SOFT = "asset_soft"
    ASSET_HARD = "asset_hard"
    RESOURCE_USAGE = "resource_usage"
    CONFIG_CHANGE = "config_change"
    COMPLIANCE_AUDIT = "compliance_audit"
    ERROR_RECORD = "error_record"
    THREAT_EVENT = "threat_event"
    INCIDENT_LOOP = "incident_loop"


@dataclass(slots=True)
class TraceSession:
    id: str
    tenant_id: str
    agent_id: str
    created_at: datetime
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class StoredTraceEvent:
    seq: int
    event_type: str
    payload: dict[str, Any]
    prev_hash: str
    row_hash: str
    created_at: datetime
