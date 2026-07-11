# -*- coding: utf-8 -*-
"""模型注册表：规范键 → pydantic 模型类。

模型在各模块定义时通过 :func:`register` 注册。未知规范必须显式返回
``None``，不能静默回退到宽松模型，否则拼写错误或尚未实现的规范会被
错误地判定为有效数据。
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

_REGISTRY: dict[str, Any] = {}


class PermissiveModel(BaseModel):
    """宽松占位模型：允许任意字段，不做严格校验。"""
    model_config = ConfigDict(extra="allow")


def register(spec_key: str, model_cls: Any) -> None:
    _REGISTRY[spec_key] = model_cls


def get_model(spec_key: str):
    return _REGISTRY.get(spec_key)
