from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import Deque, Mapping


@dataclass
class MetricBaseline:
    """
    数值型基线：CPU/内存/带宽/时延/并发等，支持阈值与简单滑动统计。
    """

    thresholds: Mapping[str, tuple[float | None, float | None]] = field(default_factory=dict)
    """metric_name -> (low_alert, high_alert)，None 表示不检查该侧。"""

    history_window: int = 64
    _history: dict[str, Deque[float]] = field(default_factory=dict, repr=False)

    def record(self, name: str, value: float) -> None:
        if name not in self._history:
            self._history[name] = deque(maxlen=self.history_window)
        self._history[name].append(value)

    def violations(self, snapshot: Mapping[str, float]) -> list[tuple[str, str, float]]:
        """返回 (metric, reason, value)。"""
        out: list[tuple[str, str, float]] = []
        for k, v in snapshot.items():
            if k not in self.thresholds:
                continue
            low, high = self.thresholds[k]
            if low is not None and v < low:
                out.append((k, f"below_baseline({low})", v))
            if high is not None and v > high:
                out.append((k, f"above_baseline({high})", v))
        return out

    def zscore_anomaly(self, name: str, value: float, sigma: float = 3.0) -> bool:
        hist = list(self._history.get(name, ()))
        if len(hist) < 5:
            return False
        m = mean(hist)
        sd = pstdev(hist)
        if sd == 0:
            return False
        return abs(value - m) > sigma * sd


@dataclass
class BehavioralBaseline:
    """
    离散行为基线：例如每小时工具调用次数、常见指令模式分布等。
    """

    expected_hourly_tool_rate: float | None = None
    allowed_tool_names: frozenset[str] | None = None

    def tool_name_outlier(self, tool_name: str) -> bool:
        if self.allowed_tool_names is None:
            return False
        return tool_name not in self.allowed_tool_names
