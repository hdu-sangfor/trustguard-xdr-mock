# -*- coding: utf-8 -*-
"""规范格式与记录包装层校验。

官方样例中存在历史版本和非标准 UUID，因此 normal 模式将这类偏差记为
warning，strict 模式才升级为 error。不会把官方样例中的兼容性变体误判为
普通模式下的无效数据。
"""
from __future__ import annotations

from typing import Any

from ..models.common import REGION_ID_PATTERN, UUID_PATTERN


_EXPECTED_VERSIONS: dict[str, set[int]] = {
    "DNS日志": {1, 111},
    "网络安全日志": {1, 121},
    "端点安全日志": {1, 124},
    "终端行为日志": {1, 108},
    "安全事件": {1, 117},
    "安全告警": {1, 130},
}

_ALLOWED_RECORD_TYPES: dict[str, set[str]] = {
    "安全事件": {"INCIDENT", "update-incident"},
    "安全告警": {"ALERT", "edr-update-alert", "ndr-update-alert"},
}


def _issue(
    *,
    strictness: str,
    errors: list[dict],
    warnings: list[dict],
    path: str,
    msg: str,
    code: str,
    value: Any,
) -> None:
    item = {"path": path, "msg": msg, "code": code, "value": value}
    if strictness == "strict":
        errors.append(item)
    else:
        warnings.append(item)


def _data_layer(record: dict) -> tuple[dict, str]:
    data = record.get("data")
    if isinstance(data, dict):
        return data, "data."
    return record, ""


def _iter_region_values(data: dict, prefix: str):
    for key, value in data.items():
        if not str(key).lower().endswith("regionid"):
            continue
        path = f"{prefix}{key}"
        if isinstance(value, list):
            for index, item in enumerate(value):
                yield f"{path}.{index}", item
        else:
            yield path, value


def validate_formats(
    spec_key: str,
    record: dict,
    strictness: str = "normal",
) -> tuple[list[dict], list[dict]]:
    """返回 ``(errors, warnings)``。

    normal 模式兼容官方样例中的历史格式；strict 模式用于检查是否完全符合
    当前规范所声明的格式。
    """
    errors: list[dict] = []
    warnings: list[dict] = []
    data, prefix = _data_layer(record)

    uuid_value = data.get("uuId")
    if uuid_value not in (None, ""):
        if not isinstance(uuid_value, str) or UUID_PATTERN.fullmatch(uuid_value) is None:
            _issue(
                strictness=strictness,
                errors=errors,
                warnings=warnings,
                path=f"{prefix}uuId",
                msg="uuId 不符合规范声明的 {类型前缀}-{10位时间戳}-{5位随机值} 格式",
                code="uuid_format",
                value=uuid_value,
            )

    for path, value in _iter_region_values(data, prefix):
        if value in (None, ""):
            continue
        if not isinstance(value, str) or REGION_ID_PATTERN.fullmatch(value) is None:
            _issue(
                strictness=strictness,
                errors=errors,
                warnings=warnings,
                path=path,
                msg="regionId 必须是 24 位十六进制字符串",
                code="region_id_format",
                value=value,
            )

    version = data.get("v")
    expected_versions = _EXPECTED_VERSIONS.get(spec_key)
    if version is not None and expected_versions:
        try:
            normalized_version = int(version)
        except (TypeError, ValueError):
            normalized_version = None
        if normalized_version not in expected_versions:
            _issue(
                strictness=strictness,
                errors=errors,
                warnings=warnings,
                path=f"{prefix}v",
                msg=f"数据版本偏离当前规范，期望值之一: {sorted(expected_versions)}",
                code="version_drift",
                value=version,
            )

    allowed_types = _ALLOWED_RECORD_TYPES.get(spec_key)
    if allowed_types is not None:
        record_type = record.get("type")
        if record_type not in allowed_types:
            errors.append(
                {
                    "path": "type",
                    "msg": f"非法记录类型，合法集合: {sorted(allowed_types)}",
                    "code": "invalid_record_type",
                    "value": record_type,
                }
            )

    for field in ("severity", "confidence"):
        value = data.get(field)
        if value in (None, ""):
            continue
        try:
            normalized_value = float(value) if not isinstance(value, bool) else None
        except (TypeError, ValueError):
            normalized_value = None
        if normalized_value is None or not 0 <= normalized_value <= 100:
            errors.append(
                {
                    "path": f"{prefix}{field}",
                    "msg": f"{field} 必须位于 0..100",
                    "code": "number_range",
                    "value": value,
                }
            )

    return errors, warnings
