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
    # 状态化 Mock 使用标准库 SQLite；相对路径以项目根目录为准。
    "state_db_path": "data/xdr_mock.sqlite3",
    # 仅 /mock/v1/** 管理接口使用。不要在 Agent/Connector 中配置此值。
    "mock_admin_token": "mock_admin_token_change_me",
    # 是否开放 /api/trustguard-mock/v1/query/** 开发扩展。
    "enable_mock_extensions": True,
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
    if os.getenv("XDR_STATE_DB_PATH"):
        cfg["state_db_path"] = os.environ["XDR_STATE_DB_PATH"]
    if os.getenv("XDR_MOCK_ADMIN_TOKEN"):
        cfg["mock_admin_token"] = os.environ["XDR_MOCK_ADMIN_TOKEN"]
    if os.getenv("XDR_ENABLE_MOCK_EXTENSIONS"):
        cfg["enable_mock_extensions"] = os.environ[
            "XDR_ENABLE_MOCK_EXTENSIONS"
        ].strip().lower() in {"1", "true", "yes", "on"}
    _CONFIG = cfg
    return cfg


def get_config() -> dict:
    if _CONFIG is None:
        load_config()
    return _CONFIG


def data_root() -> Path:
    """解析样例数据根目录（DataOpenDocument）为绝对路径。

    支持相对路径（相对项目根）与绝对路径；`XDR_DATA_ROOT` 已在 load_config 生效。
    运行时与测试共用此函数，保证解析口径一致。
    """
    cfg = get_config()
    project_root = Path(__file__).resolve().parents[1]  # xdr-mock/
    configured = Path(cfg["data_root"])
    if configured.is_absolute():
        return configured.resolve()
    return (project_root / configured).resolve()


def ensure_data_root() -> Path:
    """启动时校验样例数据目录存在，缺失则给出可操作的报错。"""
    root = data_root()
    if not root.is_dir():
        raise RuntimeError(
            f"样例数据目录不存在: {root}\n"
            "请设置环境变量 XDR_DATA_ROOT 指向 trustguard-docs 的 "
            "xdr-api-data-specs/DataOpenDocument，"
            "或将 trustguard-docs 克隆到与本项目同级的父目录。"
        )
    return root


def state_db_path() -> Path:
    """解析状态数据库路径，并保证父目录存在。"""
    configured = Path(get_config()["state_db_path"])
    if not configured.is_absolute():
        configured = Path(__file__).resolve().parents[1] / configured
    resolved = configured.resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved
