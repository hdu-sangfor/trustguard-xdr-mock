# -*- coding: utf-8 -*-
"""mock 系统配置加载。"""
from __future__ import annotations

import os
from pathlib import Path
import yaml

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 8443,
    # ak → sk 映射。客户端用对应 ak 签名，服务端据此校验。
    # 默认提供一对测试凭证（非真实密钥）。
    "credentials": {
        "test_ak_0001": "test_sk_0001_secret",
    },
    "sign_date_window_seconds": 900,  # ±15 分钟
    "validate_strictness": "normal",  # normal | strict | lenient
    "data_root": "../trustguard-docs/xdr-api-data-specs/DataOpenDocument",
}

_CONFIG = None


def load_config(path: str | Path | None = None) -> dict:
    global _CONFIG
    if _CONFIG is not None and path is None:
        return _CONFIG
    cfg = dict(DEFAULT_CONFIG)
    if path is None:
        # 默认配置文件位于项目根
        root = Path(__file__).resolve().parents[1]
        path = root / "config.yaml"
    path = Path(path)
    if path.exists():
        with open(path, encoding="utf-8") as f:
            user = yaml.safe_load(f) or {}
        # 深度合并：credentials 整体替换
        for k, v in user.items():
            cfg[k] = v
    # 容器、CI 和非标准仓库布局优先使用环境变量，避免修改本地配置文件。
    if os.getenv("XDR_DATA_ROOT"):
        cfg["data_root"] = os.environ["XDR_DATA_ROOT"]
    _CONFIG = cfg
    return cfg


def get_config() -> dict:
    if _CONFIG is None:
        load_config()
    return _CONFIG
