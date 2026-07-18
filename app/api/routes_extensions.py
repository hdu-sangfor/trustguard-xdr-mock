# -*- coding: utf-8 -*-
"""非官方、显式命名的 Agent 联调查询扩展。"""
from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import responses
from ..repositories import get_repository

router = APIRouter(prefix="/api/trustguard-mock/v1/query", tags=["mock-extension"])

_KINDS = {
    "dns": "dns",
    "endpoint-security": "endpoint_security",
    "endpoint-behavior": "endpoint_behavior",
}


async def _body(request: Request) -> dict | JSONResponse:
    try:
        value = json.loads(await request.body() or b"{}")
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content=responses.fail("invalid JSON body", 400))
    if not isinstance(value, dict):
        return JSONResponse(
            status_code=400, content=responses.fail("JSON body must be an object", 400)
        )
    return value


def _mark(payload: dict) -> dict:
    payload["x-mock-extension"] = True
    return payload


@router.post("/whitelist-match", openapi_extra={"x-mock-extension": True})
async def whitelist_match(request: Request):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    return _mark(responses.ok({"matched": get_repository().match_whitelists(obj)}))


@router.post("/{data_type}", openapi_extra={"x-mock-extension": True})
async def query_extension(data_type: str, request: Request):
    kind = _KINDS.get(data_type)
    if kind is None:
        return JSONResponse(
            status_code=404, content=responses.fail(f"unknown data type: {data_type}", 404)
        )
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    try:
        page, page_size = get_repository().pagination(obj)
        items, total = get_repository().list_records(kind, obj)
    except (TypeError, ValueError) as exc:
        return JSONResponse(
            status_code=400, content=responses.fail(f"invalid query parameter: {exc}", 400)
        )
    return _mark(responses.page(items, total, page, page_size))
