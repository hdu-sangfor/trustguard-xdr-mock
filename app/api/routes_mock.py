# -*- coding: utf-8 -*-
"""测试编排专用接口；不得由生产 Agent 调用。"""
from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import responses
from ..repositories import get_repository
from ..scenarios import available_scenarios, build_scenario

router = APIRouter(prefix="/mock/v1", tags=["mock-admin"])


@router.get("/scenarios", openapi_extra={"x-mock-admin": True})
async def scenarios():
    return responses.ok({"available": available_scenarios()})


@router.post("/scenarios/{scenario_id}:seed", openapi_extra={"x-mock-admin": True})
async def seed_scenario(scenario_id: str):
    repo = get_repository()
    try:
        scenario = build_scenario(scenario_id, int(repo.now()))
    except KeyError:
        return JSONResponse(
            status_code=404,
            content=responses.fail(
                f"unknown scenario: {scenario_id}; available={available_scenarios()}", 404
            ),
        )
    return responses.ok(repo.seed_scenario(scenario))


@router.post("/scenarios:reset", openapi_extra={"x-mock-admin": True})
async def reset_scenarios():
    count = get_repository().reset_scenarios()
    return responses.ok({"resetScenarios": count})


@router.post("/clock:advance", openapi_extra={"x-mock-admin": True})
async def advance_clock(request: Request):
    try:
        body = json.loads(await request.body() or b"{}")
        seconds = int(body.get("seconds", 0))
        now = get_repository().advance_clock(seconds)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        return JSONResponse(status_code=400, content=responses.fail(str(exc), 400))
    return responses.ok({"advancedSeconds": seconds, "mockNow": int(now)})


@router.get(
    "/scenarios/{scenario_id}/ground-truth", openapi_extra={"x-mock-admin": True}
)
async def ground_truth(scenario_id: str):
    value = get_repository().ground_truth(scenario_id)
    if value is None:
        return JSONResponse(status_code=404, content=responses.fail("scenario not seeded", 404))
    return responses.ok(value)


@router.get("/scenarios/{scenario_id}/timeline", openapi_extra={"x-mock-admin": True})
async def timeline(scenario_id: str):
    if get_repository().ground_truth(scenario_id) is None:
        return JSONResponse(status_code=404, content=responses.fail("scenario not seeded", 404))
    return responses.ok(get_repository().timeline(scenario_id))
