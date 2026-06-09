from __future__ import annotations

from mcp_agent_safe_protecter.core.baseline import MetricBaseline
from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity


class BusinessHealthDetector:
    """
    分支二：业务可用性 & 合规运行检测。
    基于基线阈值：CPU/内存/带宽、推理时延、并发与接口成功率等。
    """

    def __init__(self, metric_baseline: MetricBaseline | None = None) -> None:
        self.metrics = metric_baseline or MetricBaseline(
            thresholds={
                "cpu_percent": (None, 90.0),
                "memory_percent": (None, 92.0),
                "bandwidth_mbps": (None, 5000.0),
                "inference_latency_p99_ms": (None, 8000.0),
                "concurrent_requests": (None, 500.0),
                "api_success_rate": (0.95, None),
            }
        )

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for name, value in ctx.metrics.items():
            self.metrics.record(name, float(value))

        if ctx.session_info.get("session_anomaly"):
            findings.append(
                Finding(
                    BranchId.BUSINESS_HEALTH,
                    "session_anomaly",
                    "会话异常（标识位）",
                    str(ctx.session_info.get("session_detail", "")),
                    Severity.MEDIUM,
                    dict(ctx.session_info),
                )
            )
        if ctx.session_info.get("normal_operation") is False:
            findings.append(
                Finding(
                    BranchId.BUSINESS_HEALTH,
                    "normal_operation_degraded",
                    "正常运行监测：业务未处于合规运行状态",
                    str(ctx.session_info.get("degraded_reason", "normal_operation=false")),
                    Severity.HIGH,
                    dict(ctx.session_info),
                )
            )

        for name, reason, value in self.metrics.violations(ctx.metrics):
            findings.append(
                Finding(
                    BranchId.BUSINESS_HEALTH,
                    "metric_threshold",
                    f"指标异常: {name}",
                    f"{reason}, 当前值={value}",
                    Severity.MEDIUM,
                    {"metric": name, "value": value},
                )
            )

        for name, value in ctx.metrics.items():
            try:
                fv = float(value)
            except (TypeError, ValueError):
                continue
            if self.metrics.zscore_anomaly(name, fv):
                findings.append(
                    Finding(
                        BranchId.BUSINESS_HEALTH,
                        "metric_baseline_zscore",
                        "指标相对滑动基线异常（统计判别）",
                        name,
                        Severity.LOW,
                        {"metric": name, "value": fv},
                    )
                )

        for task in ctx.task_states:
            st = str(task.get("state") or "")
            if st in {"stuck", "dead_letter", "failed"}:
                findings.append(
                    Finding(
                        BranchId.BUSINESS_HEALTH,
                        "task_flow_abnormal",
                        "任务流转异常",
                        str(task),
                        Severity.MEDIUM,
                        dict(task),
                    )
                )

        sess = ctx.session_info
        if sess.get("long_idle_seconds", 0) > int(sess.get("idle_threshold_sec", 3600)):
            findings.append(
                Finding(
                    BranchId.BUSINESS_HEALTH,
                    "long_no_response",
                    "长时间无响应",
                    f"idle {sess['long_idle_seconds']}s",
                    Severity.LOW,
                    sess,
                )
            )
        if sess.get("request_burst_factor", 0) > float(sess.get("burst_threshold", 5.0)):
            findings.append(
                Finding(
                    BranchId.BUSINESS_HEALTH,
                    "abnormal_high_frequency",
                    "异常高频请求",
                    str(sess.get("request_burst_factor")),
                    Severity.MEDIUM,
                    sess,
                )
            )

        branches = ctx.session_info.get("executed_branches") or []
        allowed = set(ctx.session_info.get("allowed_branches") or [])
        if allowed:
            for b in branches:
                if b not in allowed:
                    findings.append(
                        Finding(
                            BranchId.BUSINESS_HEALTH,
                            "noncompliant_branch",
                            "违规业务分支执行",
                            str(b),
                            Severity.HIGH,
                            {"branch": b},
                        )
                    )

        stats = ctx.api_call_stats
        if stats:
            total = int(stats.get("total", 0))
            ok = int(stats.get("success", 0))
            if total > 0 and ok / total < 0.95:
                findings.append(
                    Finding(
                        BranchId.BUSINESS_HEALTH,
                        "api_success_rate_low",
                        "接口调用成功率偏低",
                        f"{ok}/{total}",
                        Severity.MEDIUM,
                        dict(stats),
                    )
                )

        return findings
