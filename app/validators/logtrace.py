# -*- coding: utf-8 -*-
"""logTraceInfo 节点链校验。

每类数据期望的 appName 序列：
- DNS日志 / 网络安全日志: logDetect → logUpload → collect → transfer
- 安全事件: collect → transfer → edr → alert → nae → incident
- 安全告警: collect → transfer → [alphaApp → seclog → ndr] → alert
- 端点安全日志: collect → transfer
- 终端行为日志: 无 logTraceInfo
"""
from __future__ import annotations

import json
import re

# 注册表：日志跟踪规范v1.1 的 12 个 + 样例实证的 7 个
APP_NAME_REGISTRY = {
    "cwpp-agent", "cwpp-mgr", "edr-agent", "edr-mgr",
    "collect", "transfer", "enrich", "converge",
    "alert", "incident", "docking", "storage",
    # 样例实证存在（规范未列出）
    "logDetect", "logUpload", "edr", "ndr", "nae",
    "alphaApp", "seclog",
}

# 每类数据期望的节点链（按流向顺序）。None 表示不应有 logTraceInfo。
EXPECTED_CHAINS: dict[str, list[str] | None] = {
    "DNS日志": ["logDetect", "logUpload", "collect", "transfer"],
    "网络安全日志": ["logDetect", "logUpload", "collect", "transfer"],
    "安全事件": ["collect", "transfer", "edr", "alert", "nae", "incident"],
    "安全告警": ["collect", "transfer", "alphaApp", "seclog", "ndr", "alert"],
    "端点安全日志": ["collect", "transfer"],
    "终端行为日志": None,  # 不应有
}

# 告警链中 alphaApp/seclog/ndr 是可选段（部分样例无）
_OPTIONAL_SEGMENTS = {
    "安全告警": (["alphaApp", "seclog", "ndr"],),
}


def parse_logtrace(logtrace: str) -> list[dict]:
    """解析 logTraceInfo 字符串为节点列表。"""
    if not logtrace:
        return []
    nodes = []
    for seg in str(logtrace).split("|"):
        seg = seg.strip()
        if not seg:
            continue
        try:
            nodes.append(json.loads(seg))
        except json.JSONDecodeError:
            m = re.search(r'"appName"\s*:\s*"([^"]+)"', seg)
            if m:
                nodes.append({"appName": m.group(1)})
    return nodes


def _match_chain(actual: list[str], expected: list[str], spec_key: str) -> list[str]:
    """检查 actual 是否按 expected 顺序包含（允许告警的可选段缺失）。返回问题描述列表。"""
    problems = []
    # 移除可选段中实际缺失的（告警场景）
    exp = list(expected)
    if spec_key in _OPTIONAL_SEGMENTS:
        for seg in _OPTIONAL_SEGMENTS[spec_key]:
            for s in seg:
                if s not in actual and s in exp:
                    exp.remove(s)
    # 检查 expected 中存在的节点是否按序出现在 actual 中
    ai = 0
    for name in exp:
        found = False
        while ai < len(actual):
            if actual[ai] == name:
                found = True
                ai += 1
                break
            ai += 1
        if not found:
            problems.append(f"logTraceInfo 缺少节点或顺序错误: 期望含 {name}")
    return problems


def validate_logtrace(spec_key: str, record: dict) -> list[dict]:
    """返回 warning 列表（节点链异常记为 warning，避免误杀合法变体）。"""
    warnings = []
    expected = EXPECTED_CHAINS.get(spec_key)
    if expected is None:
        # 终端行为日志不应有 logTraceInfo
        lti = record.get("logTraceInfo")
        if lti:
            warnings.append({"path": "logTraceInfo", "msg": "终端行为日志不应包含 logTraceInfo", "code": "unexpected_logtrace"})
        return warnings

    # logTraceInfo 可能在顶层或 data 层
    lti = record.get("logTraceInfo")
    if lti is None and isinstance(record.get("data"), dict):
        lti = record["data"].get("logTraceInfo")
    if not lti:
        warnings.append({"path": "logTraceInfo", "msg": "缺少 logTraceInfo 字段", "code": "missing_logtrace"})
        return warnings

    nodes = parse_logtrace(lti)
    actual = [n.get("appName", "") for n in nodes]

    # 校验 appName 在注册表内
    for n in nodes:
        name = n.get("appName", "")
        if name and name not in APP_NAME_REGISTRY:
            warnings.append({"path": "logTraceInfo", "msg": f"未知 appName: {name}", "code": "unknown_appname"})

    # 校验时间戳单调递增
    timestamps = [n.get("timestamp") for n in nodes if n.get("timestamp") is not None]
    if len(timestamps) > 1:
        for i in range(1, len(timestamps)):
            if _to_float(timestamps[i]) < _to_float(timestamps[i - 1]):
                warnings.append({"path": "logTraceInfo", "msg": "timestamp 非单调递增", "code": "non_monotonic_ts"})
                break

    # 校验节点链顺序
    problems = _match_chain(actual, list(expected), spec_key)
    for p in problems:
        warnings.append({"path": "logTraceInfo", "msg": p, "code": "chain_order"})
    return warnings


def _to_float(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0
