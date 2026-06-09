from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping

from mcp_agent_safe_protecter.core.types import Severity


class ProtectionBranchId(str, Enum):
    """安全防护七大分支（与检测编排分离，侧重事前阻断与加固建议）。"""

    SYSTEM_COMPONENT = "system_component"  # 系统与组件漏洞破坏防护
    BUSINESS_BEHAVIOR = "business_behavior"  # 业务行为风险防护
    AGENT_SELF = "agent_self"  # 智能体本体自防护
    EXTERNAL_INTRUSION = "external_intrusion"  # 外部入侵与恶意攻击防护
    PRIVILEGE_BOUNDARY = "privilege_boundary"  # 权限越权防护
    DATA_GUARD = "data_guard"  # 数据安全防护
    COUNTERSTRIKE = "counterstrike"  # 自卫对抗（仅防御剧本，见分支实现说明）


@dataclass(slots=True)
class ProtectionSignal:
    """单条防护判定：风险说明 + 建议执行的防护动作（由编排/网关消费）。"""

    branch: ProtectionBranchId
    category: str
    title: str
    detail: str
    severity: Severity
    evidence: Mapping[str, Any] = field(default_factory=dict)
    """建议动作枚举示例：block_tool、isolate_session、reject_request、revoke_token、alert_soc、rollback_config"""
    recommended_enforcement: tuple[str, ...] = ()

    detected_at: datetime = field(default_factory=datetime.utcnow)
