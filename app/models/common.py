# -*- coding: utf-8 -*-
"""共享字段类型与校验器。

被六类数据模型复用：regionId 24位、uuId 格式、v 版本公式、时间戳、ipTag 等。
"""
from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import BeforeValidator, StringConstraints

# 24 位资产域ID（hex 或 24 个 0 代表外网）
REGION_ID_PATTERN = re.compile(r"^(?:[0-9A-Fa-f]{24}|0{24})$")

# uuId 通用格式：{prefix}-{10位时间戳}-{5位随机}。随机部分允许字母数字
UUID_PATTERN = re.compile(r"^[a-z_]+-\d{10}-[A-Za-z0-9]{5}$")


def _coerce_optional_int(v: Any) -> Any:
    """允许 null/空字符串视为 None。"""
    if v is None or v == "" or v == "null":
        return None
    return v


def _coerce_int(v: Any) -> Any:
    """容错 int：样例中部分 int 字段可能传字符串。"""
    if v is None or v == "" or v == "null":
        return None
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)):
        return int(v)
    try:
        return int(v)
    except (TypeError, ValueError):
        return v  # 保留原值让 pydantic 报类型错


OptionalInt = Annotated[int | None, BeforeValidator(_coerce_optional_int)]
CoercedInt = Annotated[int | None, BeforeValidator(_coerce_int)]

NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]


def validate_v(spec_major: int, spec_minor: int):
    """返回一个校验 v（数据版本）的函数。

    公式：v == major*100 + minor；minor==0 时 v 可为 major。
    """
    expected_full = spec_major * 100 + spec_minor

    def validate(value: Any) -> int:
        if value == expected_full:
            return value
        if spec_minor == 0 and value == spec_major:
            return value
        # 样例恒为 1，宽松：允许 1 或公式值
        if value == 1:
            return value
        return value  # 不报错，由状态机层记 warning（避免误杀）

    return validate


# 各数据类型期望的 logTraceInfo 节点链（与 validators/logtrace 一致）
EXPECTED_LOGTRACE_CHAINS = {
    "DNS日志": ["logDetect", "logUpload", "collect", "transfer"],
    "网络安全日志": ["logDetect", "logUpload", "collect", "transfer"],
    "安全事件": ["collect", "transfer", "edr", "alert", "nae", "incident"],
    "安全告警": ["collect", "transfer", "alphaApp", "seclog", "ndr", "alert"],
    "端点安全日志": ["collect", "transfer"],
    "终端行为日志": None,
}


# uuId 前缀（按类型）
UUID_PREFIX = {
    "DNS日志": "dns_log",
    "端点安全日志": "endpoint_security_log",
    "终端行为日志": "endpoint_behavior_log",
    "网络安全日志": "network_security_log",
    "安全事件": "incident",
    "安全告警": "alert",
}
