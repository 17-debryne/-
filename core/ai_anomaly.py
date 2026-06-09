from __future__ import annotations

from typing import Any, Mapping, Protocol


class AIAnomalyDiscriminator(Protocol):
    """对接外部模型或专用异常检测服务的协议。"""

    def score(self, features: Mapping[str, Any]) -> float:
        """
        返回 0~1，越大越异常。具体阈值由调用方策略决定。
        """
        ...


class HeuristicAnomalyDiscriminator:
    """
    占位实现：无外部模型时，用加权特征启发式近似「AI 异常判别」。
    生产环境可替换为 ONNX/向量检索/小模型等。
    """

    def __init__(self, threshold: float = 0.65) -> None:
        self.threshold = threshold

    def score(self, features: Mapping[str, Any]) -> float:
        s = 0.0
        if features.get("prompt_injection_hits", 0):
            s += 0.35
        if features.get("privilege_escalation_hits", 0):
            s += 0.25
        if features.get("sensitive_command_hits", 0):
            s += 0.2
        if features.get("unknown_tool_calls", 0):
            s += 0.15
        if features.get("risky_tool_payloads", 0):
            s += 0.22
        if features.get("external_blocklisted_host", 0):
            s += 0.2
        return min(1.0, s)

    def is_anomaly(self, features: Mapping[str, Any]) -> bool:
        return self.score(features) >= self.threshold
