# -*- coding: utf-8 -*-
"""样例数据加载器：从 DataOpenDocument 读取真实样例。"""
from __future__ import annotations

import json
from pathlib import Path

from ..config import get_config

_CACHE: dict[str, list[dict]] = {}


def _data_root() -> Path:
    cfg = get_config()
    root = Path(__file__).resolve().parents[2]  # xdr-mock/
    configured = Path(
        cfg.get(
            "data_root",
            "../trustguard-docs/xdr-api-data-specs/DataOpenDocument",
        )
    )
    if configured.is_absolute():
        return configured.resolve()
    return (root / configured).resolve()


# 规范键 → 样例文件名
_FILE_MAP = {
    "安全告警": "安全告警规范/安全告警样例数据.txt",
    "安全事件": "安全事件规范/安全事件样例数据.txt",
    "DNS日志": "DNS日志规范/DNS日志样例数据.txt",
    "端点安全日志": "端点安全日志规范/端点安全日志样例数据.txt",
    "终端行为日志": "终端行为日志规范/终端行为日志样例数据.txt",
    "网络安全日志": "网络安全日志规范/网络安全日志样例数据.txt",
}


def load_samples(spec_key: str) -> list[dict]:
    """加载某类样例数据，逐行 JSON 解析。结果缓存。"""
    if spec_key in _CACHE:
        return _CACHE[spec_key]
    rel = _FILE_MAP.get(spec_key)
    if not rel:
        return []
    path = _data_root() / rel
    samples: list[dict] = []
    if path.exists():
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    samples.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    _CACHE[spec_key] = samples
    return samples


def all_types() -> list[str]:
    return list(_FILE_MAP.keys())
