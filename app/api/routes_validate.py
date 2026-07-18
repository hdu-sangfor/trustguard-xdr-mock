# -*- coding: utf-8 -*-
"""数据校验接口：接收数据，返回校验报告。

端点接收原始请求体字节（自行 json 解析），确保签名校验的 body 与实际 body 一致。
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import responses

router = APIRouter(prefix="/api/xdr/v1/validate", tags=["validate"])

_TYPE_MAP = {
    "alerts": "安全告警",
    "incidents": "安全事件",
    "dns": "DNS日志",
    "endpoint_security": "端点安全日志",
    "endpoint_behavior": "终端行为日志",
    "network_security": "网络安全日志",
}


def _error(message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=responses.fail(message, code=status_code),
    )


@router.post("/{data_type}", openapi_extra={"x-mock-extension": True})
async def validate_one(data_type: str, request: Request):
    """校验单条数据，返回校验报告。"""
    if data_type not in _TYPE_MAP:
        return _error(f"unknown data_type: {data_type}", 404)
    body = await request.body()
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return _error("invalid JSON body", 400)
    if not isinstance(payload, dict):
        return _error("JSON body must be an object", 400)
    from ..validators.registry import validate_record
    report = validate_record(_TYPE_MAP[data_type], payload)
    return responses.ok(report)


@router.post("/batch/{data_type}", openapi_extra={"x-mock-extension": True})
async def validate_batch(data_type: str, request: Request):
    """批量校验。body: {"records": [...]}."""
    if data_type not in _TYPE_MAP:
        return _error(f"unknown data_type: {data_type}", 404)
    body = await request.body()
    try:
        obj = json.loads(body)
    except json.JSONDecodeError:
        return _error("invalid JSON body", 400)
    if not isinstance(obj, dict):
        return _error("JSON body must be an object", 400)
    records = obj.get("records")
    if not isinstance(records, list):
        return _error("records must be an array", 400)
    if len(records) > 10000:
        return _error("records exceeds maximum size 10000", 400)
    if any(not isinstance(record, dict) for record in records):
        return _error("every record must be an object", 400)
    from ..validators.registry import validate_record
    reports = [validate_record(_TYPE_MAP[data_type], r) for r in records]
    summary = {
        "total": len(reports),
        "valid": sum(1 for r in reports if r["valid"]),
        "invalid": sum(1 for r in reports if not r["valid"]),
    }
    return responses.ok({"summary": summary, "reports": reports})
