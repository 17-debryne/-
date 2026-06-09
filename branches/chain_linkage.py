from __future__ import annotations

from typing import Any, Mapping, Sequence

from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity


class ChainLinkageDetector:
    """
    第十项：链路联动检测。
    端—边—云联动与同步、智能体—插件—第三方调用链异常与时延、
    TLS/证书中间人、链路顺序与签名篡改、非法或未登记回调及回调完整性。
    """

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        cc = ctx.call_chain

        if cc.get("edge_cloud_attestation_failed"):
            findings.append(
                Finding(
                    BranchId.CHAIN_LINKAGE,
                    "edge_cloud_mismatch",
                    "端-边-云联动校验失败",
                    str(cc.get("detail")),
                    Severity.HIGH,
                    dict(cc),
                )
            )

        if cc.get("endpoint_edge_cloud_sync_failed"):
            findings.append(
                Finding(
                    BranchId.CHAIN_LINKAGE,
                    "endpoint_edge_cloud_sync",
                    "端-边-云联动不一致或同步失败",
                    str(cc.get("sync_detail")),
                    Severity.HIGH,
                    dict(cc),
                )
            )

        findings.extend(self._chain_anomaly(cc.get("hops") or ()))
        findings.extend(self._mitm_signals(cc))
        findings.extend(self._tamper_signals(cc))
        findings.extend(
            self._callback_checks(
                cc.get("callbacks") or (),
                frozenset(cc.get("callback_allowlist") or ()),
            )
        )

        if cc.get("third_party_chain_break"):
            findings.append(
                Finding(
                    BranchId.CHAIN_LINKAGE,
                    "third_party_chain_break",
                    "智能体与插件/第三方系统调用链断裂或不可信跳转",
                    str(cc.get("break_detail")),
                    Severity.HIGH,
                    dict(cc),
                )
            )

        if cc.get("agent_plugin_latency_anomaly"):
            findings.append(
                Finding(
                    BranchId.CHAIN_LINKAGE,
                    "agent_plugin_latency_anomaly",
                    "智能体—插件—第三方链路时延或拓扑异常",
                    str(cc.get("latency_detail")),
                    Severity.MEDIUM,
                    dict(cc),
                )
            )

        if cc.get("intermediate_hijack_indicators"):
            findings.append(
                Finding(
                    BranchId.CHAIN_LINKAGE,
                    "intermediate_mitm",
                    "链路中间环节疑似劫持（证书/代理/签名异常组合）",
                    str(cc.get("mitm_detail")),
                    Severity.CRITICAL,
                    dict(cc),
                )
            )

        if cc.get("chain_span_sequence_invalid"):
            findings.append(
                Finding(
                    BranchId.CHAIN_LINKAGE,
                    "chain_sequence_tamper",
                    "调用链路顺序或父子跨度异常（疑似链路篡改）",
                    str(cc.get("sequence_detail")),
                    Severity.HIGH,
                    dict(cc),
                )
            )

        if cc.get("callback_hmac_invalid"):
            findings.append(
                Finding(
                    BranchId.CHAIN_LINKAGE,
                    "callback_integrity_fail",
                    "回调载荷完整性校验失败（疑似非法回调或篡改）",
                    str(cc.get("callback_id")),
                    Severity.HIGH,
                    dict(cc),
                )
            )

        return findings

    def _chain_anomaly(self, hops: Sequence[Mapping[str, Any]]) -> list[Finding]:
        out: list[Finding] = []
        seen: set[str] = set()
        for h in hops:
            hid = str(h.get("id") or "")
            if hid in seen:
                out.append(
                    Finding(
                        BranchId.CHAIN_LINKAGE,
                        "call_chain_loop",
                        "调用链路存在异常环或重复节点",
                        hid,
                        Severity.MEDIUM,
                        dict(h),
                    )
                )
            seen.add(hid)
            if h.get("trust") is False:
                out.append(
                    Finding(
                        BranchId.CHAIN_LINKAGE,
                        "untrusted_hop",
                        "调用链路存在未认证/不可信节点",
                        hid,
                        Severity.HIGH,
                        dict(h),
                    )
                )
        return out

    def _mitm_signals(self, cc: Mapping[str, Any]) -> list[Finding]:
        out: list[Finding] = []
        if cc.get("tls_pin_mismatch"):
            out.append(
                Finding(
                    BranchId.CHAIN_LINKAGE,
                    "mitm_tls_pin",
                    "接口 TLS 钉扎与预期不符（疑似中间人）",
                    str(cc.get("host")),
                    Severity.CRITICAL,
                    dict(cc),
                )
            )
        if cc.get("cert_chain_invalid"):
            out.append(
                Finding(
                    BranchId.CHAIN_LINKAGE,
                    "mitm_cert_chain",
                    "证书链校验失败",
                    str(cc.get("host")),
                    Severity.CRITICAL,
                    dict(cc),
                )
            )
        return out

    def _tamper_signals(self, cc: Mapping[str, Any]) -> list[Finding]:
        out: list[Finding] = []
        if cc.get("request_signature_invalid"):
            out.append(
                Finding(
                    BranchId.CHAIN_LINKAGE,
                    "chain_tamper",
                    "调用链路完整性签名校验失败（疑似篡改）",
                    str(cc.get("span_id")),
                    Severity.CRITICAL,
                    dict(cc),
                )
            )
        if cc.get("trace_id_mismatch"):
            out.append(
                Finding(
                    BranchId.CHAIN_LINKAGE,
                    "trace_tamper",
                    "全链路追踪 ID 不一致",
                    str(cc.get("expected")) + " != " + str(cc.get("actual")),
                    Severity.HIGH,
                    dict(cc),
                )
            )
        return out

    def _callback_checks(
        self,
        callbacks: Sequence[Mapping[str, Any]],
        allow: frozenset[str],
    ) -> list[Finding]:
        out: list[Finding] = []
        for cb in callbacks:
            url = str(cb.get("url") or "")
            if cb.get("illegal") is True:
                out.append(
                    Finding(
                        BranchId.CHAIN_LINKAGE,
                        "illegal_callback",
                        "非法回调或未登记回调",
                        url,
                        Severity.HIGH,
                        dict(cb),
                    )
                )
            elif allow and url and url not in allow:
                out.append(
                    Finding(
                        BranchId.CHAIN_LINKAGE,
                        "callback_not_allowlisted",
                        "回调地址不在白名单",
                        url,
                        Severity.MEDIUM,
                        dict(cb),
                    )
                )
        return out
