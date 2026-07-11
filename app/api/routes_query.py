# -*- coding: utf-8 -*-
"""六类数据查询接口与官方资产/告警/事件查询兼容入口。"""
from __future__ import annotations

import json

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from . import responses
from ..generators.loader import load_samples
from ..generators.synthetic import generate as gen_synthetic

router = APIRouter(prefix="/api/xdr/v1", tags=["query"])

_TYPE_MAP = {
    "alerts": "安全告警",
    "incidents": "安全事件",
    "dns": "DNS日志",
    "endpoint_security": "端点安全日志",
    "endpoint_behavior": "终端行为日志",
    "network_security": "网络安全日志",
}

_ASSETS = [
    {"assetId": "A12345678", "hostIp": "192.168.75.35", "name": "demo-host"},
    {"assetId": "A12345679", "hostIp": "10.0.0.30", "name": "demo-host2"},
]


def _error(message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=responses.fail(message, code=status_code),
    )


def _records_page(
    *,
    spec_key: str,
    page: int,
    page_size: int,
    start_timestamp: int | None,
    end_timestamp: int | None,
    generate: bool,
    count: int | None,
):
    if start_timestamp is not None and end_timestamp is not None and start_timestamp > end_timestamp:
        return _error("startTimestamp must be <= endTimestamp", 400)

    if generate:
        records = gen_synthetic(
            spec_key,
            count=count or page_size,
            start_timestamp=start_timestamp,
            end_timestamp=end_timestamp,
        )
    else:
        records = load_samples(spec_key)
        filtered = []
        for record in records:
            ts = _extract_ts(record)
            if start_timestamp is not None and ts is not None and ts < start_timestamp:
                continue
            if end_timestamp is not None and ts is not None and ts > end_timestamp:
                continue
            filtered.append(record)
        records = filtered

    total = len(records)
    start = (page - 1) * page_size
    return responses.page(records[start:start + page_size], total, page, page_size)


async def _json_object(request: Request) -> dict | JSONResponse:
    body = await request.body()
    if not body:
        return {}
    try:
        value = json.loads(body)
    except json.JSONDecodeError:
        return _error("invalid JSON body", 400)
    if not isinstance(value, dict):
        return _error("JSON body must be an object", 400)
    return value


# 必须在 /{data_type}/list 之前声明，否则 GET /assets/list 会被动态路由捕获。
@router.get("/assets/list")
async def assets_list(
    page: int = Query(1, ge=1),
    pageSize: int = Query(10, ge=1, le=500),
):
    """SDK demo 使用的 GET 兼容接口。"""
    start = (page - 1) * pageSize
    return responses.page(_ASSETS[start:start + pageSize], len(_ASSETS), page, pageSize)


@router.post("/assets/list")
async def assets_list_official(request: Request):
    """官方 OpenAPI 使用 POST 查询资产。"""
    obj = await _json_object(request)
    if isinstance(obj, JSONResponse):
        return obj
    try:
        page = max(1, int(obj.get("page", 1)))
        page_size = min(500, max(1, int(obj.get("pageSize", 10))))
    except (TypeError, ValueError):
        return _error("page and pageSize must be integers", 400)

    assets = list(_ASSETS)
    asset_ids = obj.get("assetIds")
    if isinstance(asset_ids, list) and asset_ids:
        wanted = {str(value) for value in asset_ids}
        assets = [asset for asset in assets if asset["assetId"] in wanted]
    ip = str(obj.get("ip") or "").strip()
    if ip:
        assets = [asset for asset in assets if ip in asset["hostIp"]]

    start = (page - 1) * page_size
    return responses.page(assets[start:start + page_size], len(assets), page, page_size)


@router.get("/assets/department")
async def assets_department():
    return responses.ok([{"id": 1, "name": "研发部"}, {"id": 2, "name": "运维部"}])


@router.post("/alerts/list")
async def alerts_list_official(request: Request):
    return await _official_list("alerts", request)


@router.post("/incidents/list")
async def incidents_list_official(request: Request):
    return await _official_list("incidents", request)


async def _official_list(data_type: str, request: Request):
    obj = await _json_object(request)
    if isinstance(obj, JSONResponse):
        return obj
    try:
        page = max(1, int(obj.get("page", 1)))
        page_size = min(500, max(1, int(obj.get("pageSize", 20))))
        start_ts = int(obj["startTimestamp"]) if obj.get("startTimestamp") is not None else None
        end_ts = int(obj["endTimestamp"]) if obj.get("endTimestamp") is not None else None
        count = int(obj["count"]) if obj.get("count") is not None else None
    except (TypeError, ValueError):
        return _error("invalid pagination or timestamp parameter", 400)
    if count is not None and not 1 <= count <= 10000:
        return _error("count must be between 1 and 10000", 400)
    return _records_page(
        spec_key=_TYPE_MAP[data_type],
        page=page,
        page_size=page_size,
        start_timestamp=start_ts,
        end_timestamp=end_ts,
        generate=bool(obj.get("generate", False)),
        count=count,
    )


@router.get("/{data_type}/list")
async def list_data(
    data_type: str,
    page: int = Query(1, ge=1),
    pageSize: int = Query(20, ge=1, le=500),
    startTimestamp: int | None = None,
    endTimestamp: int | None = None,
    generate: bool = Query(False, description="返回参数化生成的数据"),
    count: int | None = Query(None, ge=1, le=10000, description="生成条数"),
):
    """分页查询某类数据；保留原有 GET 调试接口。"""
    if data_type not in _TYPE_MAP:
        return _error(f"unknown data_type: {data_type}", 404)
    return _records_page(
        spec_key=_TYPE_MAP[data_type],
        page=page,
        page_size=pageSize,
        start_timestamp=startTimestamp,
        end_timestamp=endTimestamp,
        generate=generate,
        count=count,
    )


def _extract_ts(record: dict) -> int | None:
    """从记录中提取代表时间戳（兼容单层/双层）。"""
    for key in ("recordTimestamp", "occurTimestamp", "sendTime"):
        value = record.get(key)
        if isinstance(value, int):
            return value
    data = record.get("data")
    if isinstance(data, dict):
        for key in ("occurTimestamp", "startTimestamp", "uploadTimestamp"):
            value = data.get(key)
            if isinstance(value, int):
                return value
    return None
