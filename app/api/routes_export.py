# -*- coding: utf-8 -*-
"""批量导出接口：每行一条 JSON（对齐样例文件格式）。"""
from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, PlainTextResponse

from . import responses
from ..generators.loader import load_samples
from ..generators.synthetic import generate as gen_synthetic
from ..generators.exporter import export_to_text

router = APIRouter(prefix="/api/xdr/v1/export", tags=["export"])

_TYPE_MAP = {
    "alerts": "安全告警",
    "incidents": "安全事件",
    "dns": "DNS日志",
    "endpoint_security": "端点安全日志",
    "endpoint_behavior": "终端行为日志",
    "network_security": "网络安全日志",
}


@router.get("/{data_type}", openapi_extra={"x-mock-extension": True})
async def export_data(
    data_type: str,
    count: int = Query(10, ge=1, le=10000),
    generate: bool = Query(False, description="导出参数化生成的数据"),
):
    """导出指定数量的样例数据，每行一条 JSON。"""
    if data_type not in _TYPE_MAP:
        return JSONResponse(
            status_code=404,
            content=responses.fail(f"unknown data_type: {data_type}", code=404),
        )
    spec_key = _TYPE_MAP[data_type]

    if generate:
        records = gen_synthetic(spec_key, count=count)
    else:
        samples = load_samples(spec_key)
        records = []
        i = 0
        while len(records) < count and samples:
            records.append(samples[i % len(samples)])
            i += 1
    text = export_to_text(records)
    return PlainTextResponse(text)
