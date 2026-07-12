# -*- coding: utf-8 -*-
"""FastAPI 入口。"""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Response

from .api import responses
from .api.routes_query import router as query_router
from .api.routes_validate import router as validate_router
from .api.routes_export import router as export_router
from .config import ensure_data_root
from .signing.verifier import verify_request_async


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动即校验规范数据在场，缺失则拒绝启动并给出可操作提示
    ensure_data_root()
    yield


app = FastAPI(
    title="Sangfor XDR Mock",
    description="深信服 XDR 平台 mock 系统：样例输出 + 严格校验 + 接口服务",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health(response: Response):
    """健康检查，同时提供与验签逻辑一致的服务端签名时钟。"""
    now = datetime.now().astimezone()
    offset = now.utcoffset()
    response.headers["Cache-Control"] = "no-store"
    return {
        "status": "ok",
        # 官方 SDK 使用本地时间字段并保留字面量 Z；验签器也按服务端本地时间比较。
        "signDate": now.strftime("%Y%m%dT%H%M%SZ"),
        "serverTime": now.isoformat(),
        "serverTimeUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "timezoneOffsetSeconds": int(offset.total_seconds()) if offset is not None else 0,
    }


# 所有业务路由都依赖签名校验
app.include_router(query_router, dependencies=[Depends(verify_request_async)])
app.include_router(validate_router, dependencies=[Depends(verify_request_async)])
app.include_router(export_router, dependencies=[Depends(verify_request_async)])
