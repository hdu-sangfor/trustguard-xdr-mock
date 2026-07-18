# -*- coding: utf-8 -*-
"""统一响应封装，对齐原系统返回结构。"""
from __future__ import annotations

from typing import Any


def ok(data: Any = None, msg: str = "success") -> dict:
    # 官方不同版本文档分别出现 message/item；历史 Mock 使用 msg/list。
    # 同时返回别名，让 SDK 联调与现有调用方都能消费。
    return {"code": 0, "msg": msg, "message": msg, "data": data}


def fail(msg: str = "failed", code: int = -1, data: Any = None) -> dict:
    return {"code": code, "msg": msg, "message": msg, "data": data}


def page(list_: list, total: int, page: int, page_size: int) -> dict:
    return ok(
        {
            "item": list_,
            "list": list_,
            "total": total,
            "page": page,
            "pageSize": page_size,
        }
    )
