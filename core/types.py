from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping, MutableMapping, Sequence


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BranchId(str, Enum):
    GLOBAL_THREAT = "global_threat"
    BUSINESS_HEALTH = "business_health"
    ASSET_INTEGRITY = "asset_integrity"
    SELF_TRUST = "self_trust"
    ACCESS_CONTROL = "access_control"
    BEHAVIOR_AUDIT = "behavior_audit"
    DATA_SECURITY = "data_security"
    ENVIRONMENT_TRUST = "environment_trust"
    ESCAPE_ABUSE = "escape_abuse"
    CHAIN_LINKAGE = "chain_linkage"
    COMPLIANCE_POLICY = "compliance_policy"
    EMERGENCY_SELF_HEAL = "emergency_self_heal"
    TRACEABILITY = "traceability"


@dataclass(frozen=True, slots=True)
class Finding:
    """单条检测结果，可序列化对接 SIEM / 审计平台。"""

    branch: BranchId
    category: str
    title: str
    detail: str
    severity: Severity
    evidence: Mapping[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.utcnow)


@dataclass(slots=True)
class ScanContext:
    """
    一次扫描的输入上下文：由各采集器填充，检测分支只读消费。
    未提供的字段由分支使用安全默认值或跳过子项。
    """

    # 通用
    agent_id: str = ""
    tenant_id: str = ""
    now: datetime = field(default_factory=datetime.utcnow)

    # 提示词 / 指令 / 工具调用（全域威胁、数据安全）
    last_user_prompt: str | None = None
    last_model_output: str | None = None
    tool_calls: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    raw_http_requests: Sequence[Mapping[str, Any]] = field(default_factory=tuple)

    # 业务与资源指标（业务可用性）
    metrics: Mapping[str, float] = field(default_factory=dict)
    task_states: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    api_call_stats: Mapping[str, Any] = field(default_factory=dict)
    session_info: Mapping[str, Any] = field(default_factory=dict)

    # 资产清单与运行时快照（完整性）
    file_manifest: Mapping[str, str] = field(default_factory=dict)  # path -> sha256
    file_actual_hashes: Mapping[str, str] = field(default_factory=dict)
    config_snapshots: MutableMapping[str, str] = field(default_factory=dict)
    memory_module_hashes: Mapping[str, str] = field(default_factory=dict)
    env_snapshot: Mapping[str, str] = field(default_factory=dict)
    registry_snapshot: Mapping[str, str] = field(default_factory=dict)

    # 权限与身份（访问控制）
    principal: Mapping[str, Any] = field(default_factory=dict)
    rbac_policy: Mapping[str, Any] = field(default_factory=dict)
    attempted_action: Mapping[str, Any] = field(default_factory=dict)

    # 行为审计事件流
    behavior_events: Sequence[Mapping[str, Any]] = field(default_factory=tuple)

    # 环境与宿主
    environment_profile: Mapping[str, Any] = field(default_factory=dict)

    # 智能体自检专用
    self_check: Mapping[str, Any] = field(default_factory=dict)

    # 第九项 逃逸越权专项：如 jailbreak_suspected、unknown_outbound_hosts、
    # security_policy_self_modify、security_detection_disabled、llm_role_boundary_violation 等
    escape_abuse: Mapping[str, Any] = field(default_factory=dict)

    # 第十项 链路联动：如 hops、callbacks、tls_pin_mismatch、endpoint_edge_cloud_sync_failed、
    # agent_plugin_latency_anomaly、callback_hmac_invalid 等
    call_chain: Mapping[str, Any] = field(default_factory=dict)

    # 第十一项 合规策略：如 tampered_components、hash_mismatch、missing_policies、
    # rule_conflicts、disabled_controls、signed_policy_invalid、whitelists 等
    compliance_policy_state: Mapping[str, Any] = field(default_factory=dict)

    # 第十二项 应急自愈：如 isolation_applied、circuit_breaker_open、rollback_done、
    # termination_done、action_ledger、closed_loop_verified、detection_to_response_ms 等
    healing_pipeline: Mapping[str, Any] = field(default_factory=dict)

    # 第三项 溯源全链路（操作/流转/数据变更/资产/合规/错误/威胁/事故闭环）
    traceability: Mapping[str, Any] = field(default_factory=dict)
    # 与持久化溯源会话关联（配合 SQLiteTraceStore + TraceabilityService）
    trace_session_id: str = ""
