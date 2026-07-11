# -*- coding: utf-8 -*-
"""统一响应封装，对齐原系统返回结构。"""
from __future__ import annotations

from typing import Any


def ok(data: Any = None, msg: str = "success") -> dict:
    return {"code": 0, "msg": msg, "data": data}


def fail(msg: str = "failed", code: int = -1, data: Any = None) -> dict:
    return {"code": code, "msg": msg, "data": data}


def page(list_: list, total: int, page: int, page_size: int) -> dict:
    return ok({"list": list_, "total": total, "page": page, "pageSize": page_size})
