from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Mapping

from mcp_agent_safe_protecter.core.types import BranchId, Finding, ScanContext, Severity


class AssetIntegrityDetector:
    """
    分支三：全资产静态与运行时完整性。
    覆盖程序、配置、模型、知识库/向量库、插件脚本、策略、审计日志、注册表、环境变量；
    并支持内存模块哈希对比、动态库劫持可疑路径、配置热篡改。
    """

    _HIJACK_PATH_HINTS: tuple[str, ...] = (
        "temp",
        "downloads",
        "appdata\\local\\temp",
        "/tmp/",
    )

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for path, expected in ctx.file_manifest.items():
            actual = ctx.file_actual_hashes.get(path)
            if actual is None:
                findings.append(
                    Finding(
                        BranchId.ASSET_INTEGRITY,
                        "file_missing",
                        "资产文件缺失或不可读",
                        path,
                        Severity.HIGH,
                        {"path": path},
                    )
                )
            elif actual != expected:
                findings.append(
                    Finding(
                        BranchId.ASSET_INTEGRITY,
                        "file_hash_mismatch",
                        "静态文件哈希不一致",
                        path,
                        Severity.CRITICAL,
                        {"path": path, "expected": expected, "actual": actual},
                    )
                )

        for mod, mem_hash in ctx.memory_module_hashes.items():
            disk = ctx.file_actual_hashes.get(mod) or ctx.file_manifest.get(mod)
            if disk and disk != mem_hash:
                findings.append(
                    Finding(
                        BranchId.ASSET_INTEGRITY,
                        "runtime_memory_integrity",
                        "运行时内存映像与基线不一致",
                        mod,
                        Severity.CRITICAL,
                        {"module": mod, "memory_hash": mem_hash, "disk_hash": disk},
                    )
                )

        for mod_path in ctx.memory_module_hashes:
            low = mod_path.lower()
            if any(h in low for h in self._HIJACK_PATH_HINTS):
                findings.append(
                    Finding(
                        BranchId.ASSET_INTEGRITY,
                        "dll_hijack_suspect",
                        "动态库自非可信目录加载（可疑劫持）",
                        mod_path,
                        Severity.HIGH,
                        {"path": mod_path},
                    )
                )

        hot = ctx.self_check.get("config_hot_reload_events") or []
        for ev in hot:
            if ev.get("hash_changed"):
                findings.append(
                    Finding(
                        BranchId.ASSET_INTEGRITY,
                        "config_hot_tamper",
                        "配置热更新/热篡改校验触发",
                        str(ev.get("path")),
                        Severity.HIGH,
                        dict(ev),
                    )
                )

        exp_env = ctx.self_check.get("expected_env") or {}
        exp_reg = ctx.self_check.get("expected_registry") or {}
        findings.extend(
            self._map_drift(ctx.env_snapshot, exp_env, "env_var_drift", "环境变量漂移")
        )
        findings.extend(
            self._map_drift(
                ctx.registry_snapshot, exp_reg, "registry_drift", "注册表项漂移"
            )
        )

        vs = ctx.self_check.get("vector_store_manifest") or {}
        if isinstance(vs, dict) and vs:
            expected = vs.get("path_sha256") or vs.get("expected") or {}
            actual = vs.get("actual_sha256") or vs.get("actual") or {}
            if isinstance(expected, dict) and isinstance(actual, dict):
                for path, exp_hash in expected.items():
                    got = actual.get(path)
                    if got is None:
                        findings.append(
                            Finding(
                                BranchId.ASSET_INTEGRITY,
                                "vector_store_missing",
                                "知识库/向量库资产缺失",
                                str(path),
                                Severity.HIGH,
                                {"path": path},
                            )
                        )
                    elif exp_hash and got != exp_hash:
                        findings.append(
                            Finding(
                                BranchId.ASSET_INTEGRITY,
                                "vector_store_hash_mismatch",
                                "知识库/向量库完整性与基线不一致",
                                str(path),
                                Severity.CRITICAL,
                                {"path": path, "expected": exp_hash, "actual": got},
                            )
                        )

        policy_paths = ctx.self_check.get("policy_rule_paths") or []
        if isinstance(policy_paths, list):
            for p in policy_paths:
                ps = str(p)
                if ps and ps not in ctx.file_manifest and ps not in ctx.file_actual_hashes:
                    findings.append(
                        Finding(
                            BranchId.ASSET_INTEGRITY,
                            "policy_rule_untracked",
                            "策略规则文件未纳入静态清单校验",
                            ps,
                            Severity.MEDIUM,
                            {"path": ps},
                        )
                    )

        return findings

    @staticmethod
    def _map_drift(
        current: Mapping[str, str],
        expected: Mapping[str, str],
        category: str,
        title: str,
    ) -> list[Finding]:
        if not expected:
            return []
        out: list[Finding] = []
        for k, v in expected.items():
            if current.get(k) != v:
                out.append(
                    Finding(
                        BranchId.ASSET_INTEGRITY,
                        category,
                        title,
                        k,
                        Severity.HIGH,
                        {"key": k, "expected": v, "actual": current.get(k)},
                    )
                )
        return out

    @staticmethod
    def sha256_file(path: str | Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
