from __future__ import annotations

import time

from prometheus_client import Counter, Histogram

EVALUATE_TOTAL = Counter(
    "masp_evaluate_total",
    "溯源 evaluate（scan）调用次数",
)
EVALUATE_BLOCKED_TOTAL = Counter(
    "masp_evaluate_blocked_total",
    "evaluate 结果命中阻断启发式（存在 critical severity）的次数",
)
EVALUATE_DURATION_SECONDS = Histogram(
    "masp_evaluate_duration_seconds",
    "evaluate wall time（秒）",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)
REMOTE_CONFIG_FETCH_FAILURES = Counter(
    "masp_remote_config_fetch_failures_total",
    "远程配置（Vault/Nacos）拉取失败次数（非 strict 中止时也会递增）",
)


def observe_evaluate_completed(duration_sec: float, blocked: bool) -> None:
    EVALUATE_TOTAL.inc()
    EVALUATE_DURATION_SECONDS.observe(max(0.0, duration_sec))
    if blocked:
        EVALUATE_BLOCKED_TOTAL.inc()


def evaluate_wall_clock() -> float:
    return time.perf_counter()
