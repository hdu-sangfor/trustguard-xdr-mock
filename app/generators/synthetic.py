# -*- coding: utf-8 -*-
"""参数化样例数据生成器。

基于真实样例为模板，替换时间戳/uuId/IP 等变量，保证生成的数据自身能通过校验。
支持 count / time_range / state_distribution 等参数。
"""
from __future__ import annotations

import random
import time
from typing import Any

from .loader import load_samples
from ..models.common import UUID_PREFIX

# 各类型时间戳字段（用于平移）
_TS_FIELDS_SINGLE = ["recordTimestamp", "uploadTimestamp", "insertTimestamp", "cloudTs"]
_TS_FIELDS_DOUBLE = ["occurTimestamp", "firstTimestamp", "lastTimestamp", "uploadTimestamp"]


def _shift_ts(value: Any, delta: int) -> Any:
    if isinstance(value, int):
        return value + delta
    if isinstance(value, float):
        return value + delta
    return value


def _new_uuid(prefix: str, ts: int) -> str:
    rand = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=5))
    return f"{prefix}-{ts}-{rand}"


def _random_ip() -> str:
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def generate(
    spec_key: str,
    count: int = 1,
    start_timestamp: int | None = None,
    end_timestamp: int | None = None,
    seed: int | None = None,
) -> list[dict]:
    """生成 count 条合规样例数据。

    - start_timestamp/end_timestamp：生成数据的 recordTimestamp 落在该范围内
    - seed：随机种子（可复现）
    """
    if seed is not None:
        random.seed(seed)
    templates = load_samples(spec_key)
    if not templates:
        return []

    now = int(time.time())
    if start_timestamp is None:
        start_timestamp = now - 86400
    if end_timestamp is None:
        end_timestamp = now
    if start_timestamp > end_timestamp:
        raise ValueError("start_timestamp must be <= end_timestamp")

    records: list[dict] = []
    import copy
    for i in range(count):
        tpl = copy.deepcopy(templates[i % len(templates)])
        # 生成目标时间戳
        target_ts = random.randint(start_timestamp, end_timestamp)
        # 计算与模板 recordTimestamp 的偏移
        ref_ts = _get_ref_ts(tpl, spec_key)
        delta = target_ts - ref_ts if ref_ts else 0

        # 平移所有时间戳字段
        _apply_ts_shift(tpl, spec_key, delta)

        # 更新 uuId（保持格式合规）
        prefix = UUID_PREFIX.get(spec_key)
        if prefix:
            _set_uuid(tpl, spec_key, _new_uuid(prefix, target_ts))

        records.append(tpl)
    return records


def _get_ref_ts(record: dict, spec_key: str) -> int | None:
    data = record.get("data", record) if isinstance(record.get("data"), dict) else record
    for f in ("recordTimestamp", "occurTimestamp"):
        v = data.get(f)
        if isinstance(v, int):
            return v
    return None


def _apply_ts_shift(record: dict, spec_key: str, delta: int):
    """递归平移时间戳字段。"""
    def shift_obj(obj):
        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                if isinstance(v, (dict, list)):
                    shift_obj(v)
                elif k in _TS_FIELDS_SINGLE or k in _TS_FIELDS_DOUBLE or "Timestamp" in k or "CloudTs" in k:
                    obj[k] = _shift_ts(v, delta)
        elif isinstance(obj, list):
            for item in obj:
                shift_obj(item)
    shift_obj(record)


def _set_uuid(record: dict, spec_key: str, new_uuid: str):
    if isinstance(record.get("data"), dict):
        if "uuId" in record["data"] or record["data"].get("uuId"):
            record["data"]["uuId"] = new_uuid
    else:
        if "uuId" in record:
            record["uuId"] = new_uuid
