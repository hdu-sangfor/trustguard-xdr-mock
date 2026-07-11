# -*- coding: utf-8 -*-
"""时间不变式校验。

可靠不变式：insertTimestamp >= uploadTimestamp（不强制 record <= upload，DNS 样例有反例）。
cloudTs ≈ recordTimestamp + (gwTimestamp - uploadTimestamp)，gwTimestamp 不展示，宽松校验。
recordTime/uploadTime 字符串与时间戳一致性（容忍尾空格）。
"""
from __future__ import annotations

from datetime import datetime, timezone


def _get(record: dict, *keys):
    for k in keys:
        v = record.get(k)
        if v is not None:
            return v
    return None


def validate_time(spec_key: str, record: dict) -> list[dict]:
    warnings = []
    # 取 data 层（事件/告警）或顶层
    data = record.get("data", record) if isinstance(record.get("data"), dict) else record

    upload_ts = _get(data, "uploadTimestamp")
    insert_ts = _get(data, "insertTimestamp")
    record_ts = _get(data, "recordTimestamp")
    cloud_ts = _get(data, "cloudTs")

    if isinstance(upload_ts, int) and isinstance(insert_ts, int):
        if insert_ts < upload_ts:
            warnings.append({
                "path": "insertTimestamp",
                "msg": f"insertTimestamp({insert_ts}) < uploadTimestamp({upload_ts})",
                "code": "time_invariant",
            })

    # cloudTs 宽松：应接近 recordTimestamp（gwTimestamp - uploadTimestamp 通常为小值或 0）
    if isinstance(cloud_ts, (int, float)) and isinstance(record_ts, int):
        diff = abs(cloud_ts - record_ts)
        # 允许较大偏差（gwTimestamp 未知），仅当偏差异常大时提示
        if diff > 86400 * 30:  # 30 天
            warnings.append({
                "path": "cloudTs",
                "msg": f"cloudTs 与 recordTimestamp 偏差过大: {diff}s",
                "code": "cloudts_drift",
            })

    # recordTime 字符串与 recordTimestamp 一致性
    record_time_str = _get(data, "recordTime")
    if isinstance(record_time_str, str) and isinstance(record_ts, int):
        _check_str_ts(record_time_str, record_ts, "recordTime", warnings)
    upload_time_str = _get(data, "uploadTime")
    if isinstance(upload_time_str, str) and isinstance(upload_ts, int):
        _check_str_ts(upload_time_str, upload_ts, "uploadTime", warnings)

    return warnings


def _check_str_ts(time_str: str, ts: int, field: str, warnings: list):
    """检查字符串时间与 epoch 秒是否同一天（宽松，因时区/格式差异）。"""
    s = time_str.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.000", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            # 比较 epoch 的日期部分（忽略时区）
            ts_dt = datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
            if abs((dt - ts_dt).total_seconds()) > 86400:
                warnings.append({
                    "path": field,
                    "msg": f"{field}({s}) 与时间戳({ts}) 日期不一致",
                    "code": "time_str_mismatch",
                })
            return
        except ValueError:
            continue
