"""Mock 专用路由依赖。"""
from __future__ import annotations

import hmac

from fastapi import Header, HTTPException

from ..config import get_config


async def require_mock_extensions_enabled() -> None:
    if not bool(get_config().get("enable_mock_extensions", True)):
        raise HTTPException(status_code=404, detail="mock query extensions are disabled")


async def require_mock_admin(
    x_mock_admin_token: str | None = Header(None, alias="X-Mock-Admin-Token"),
) -> None:
    expected = str(get_config().get("mock_admin_token") or "")
    if not expected or not x_mock_admin_token or not hmac.compare_digest(
        expected, x_mock_admin_token
    ):
        raise HTTPException(status_code=403, detail="invalid X-Mock-Admin-Token")
