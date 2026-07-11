# -*- coding: utf-8 -*-
"""FastAPI 入口。"""
from __future__ import annotations

from fastapi import Depends, FastAPI

from .api import responses
from .api.routes_query import router as query_router
from .api.routes_validate import router as validate_router
from .api.routes_export import router as export_router
from .signing.verifier import verify_request_async

app = FastAPI(
    title="Sangfor XDR Mock",
    description="深信服 XDR 平台 mock 系统：样例输出 + 严格校验 + 接口服务",
    version="1.0.0",
)


@app.get("/health")
async def health():
    return {"status": "ok"}


# 所有业务路由都依赖签名校验
app.include_router(query_router, dependencies=[Depends(verify_request_async)])
app.include_router(validate_router, dependencies=[Depends(verify_request_async)])
app.include_router(export_router, dependencies=[Depends(verify_request_async)])
