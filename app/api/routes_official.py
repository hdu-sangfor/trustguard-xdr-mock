# -*- coding: utf-8 -*-
"""官方 XDR OpenAPI 核心接口的状态化兼容实现。"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import responses
from ..repositories import get_repository

router = APIRouter(prefix="/api/xdr/v1", tags=["official-compatible"])


def _error(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse(status_code=status, content=responses.fail(message, status))


async def _body(request: Request) -> dict | JSONResponse:
    raw = await request.body()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return _error("invalid JSON body")
    if not isinstance(value, dict):
        return _error("JSON body must be an object")
    return value


def _page(repo_items: tuple[list[dict], int], body: dict) -> dict:
    items, total = repo_items
    page, page_size = get_repository().pagination(body)
    return responses.page(items, total, page, page_size)


@router.put("/assets/list")
async def upsert_assets(request: Request):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    raw_items = obj.get("item", obj.get("list", obj.get("assets", [obj])))
    items = raw_items if isinstance(raw_items, list) else [raw_items]
    if not items or not all(isinstance(item, dict) for item in items):
        return _error("asset item must be an object or object list")
    try:
        count = get_repository().upsert_assets(items)
    except ValueError as exc:
        return _error(str(exc))
    return responses.ok({"total": count, "succeededNum": count})


@router.delete("/assets/list")
async def delete_assets(request: Request):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    ids = obj.get("assetIds", obj.get("hostAssetIds", []))
    if not isinstance(ids, list) or not ids:
        return _error("assetIds is required")
    count = get_repository().delete_assets([str(item) for item in ids])
    return responses.ok({"total": len(ids), "succeededNum": count})


@router.post("/alerts/dealstatus")
async def deal_alerts(request: Request):
    return await _deal_records("alerts", request)


@router.post("/incidents/dealstatus")
async def deal_incidents(request: Request):
    return await _deal_records("incidents", request)


async def _deal_records(kind: str, request: Request):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    uuids = obj.get("uuIds")
    if not isinstance(uuids, list) or not uuids:
        return _error("uuIds is required")
    if "dealStatus" not in obj:
        return _error("dealStatus is required")
    total, succeeded = get_repository().update_deal_status(
        kind, [str(item) for item in uuids], obj["dealStatus"], str(obj.get("dealComment", ""))
    )
    return responses.ok({"total": total, "succeededNum": succeeded})


@router.get("/alerts/{record_uuid}/proof")
async def alert_proof(record_uuid: str):
    return _proof("alerts", record_uuid)


@router.get("/incidents/{record_uuid}/proof")
async def incident_proof(record_uuid: str):
    return _proof("incidents", record_uuid)


def _proof(kind: str, record_uuid: str):
    record = get_repository().get_record(kind, record_uuid)
    if record is None:
        return _error(f"{kind} record not found", 404)
    proof = record.get("proof")
    if not isinstance(proof, dict):
        proof = {
            "logIds": record.get("logIds", record.get("alertIds", [])),
            "processChain": record.get("processChain", []),
            "attackStory": record.get("attackStory", []),
            "description": record.get("proofDescription", record.get("description", "")),
        }
    return responses.ok(
        {
            "name": record.get("name", ""),
            "uuId": record_uuid,
            "severity": record.get("severity"),
            "threatDefine": record.get("threatDefine"),
            "direction": record.get("direction"),
            "attackResult": record.get("attackResult"),
            "proofType": record.get("proofType", 1),
            "proof": proof,
        }
    )


@router.get("/incidents/{record_uuid}/entities/{entity_type}")
async def incident_entities(record_uuid: str, entity_type: str):
    allowed = {"dns", "innerip", "ip", "host", "file", "process"}
    if entity_type not in allowed:
        return _error("unsupported entity type", 404)
    record = get_repository().get_record("incidents", record_uuid)
    if record is None:
        return _error("incident record not found", 404)
    values: list[Any] = []
    if entity_type in {"ip", "innerip"}:
        for key in ("hostIp", "srcIp", "dstIp"):
            value = record.get(key)
            values.extend(value if isinstance(value, list) else [value] if value else [])
    elif entity_type == "host":
        values = [{"hostIp": record.get("hostIp"), "assetId": record.get("assetId", "")}]
    else:
        values = record.get(f"{entity_type}Entities", [])
    return responses.ok(values)


@router.post("/securitylog/list")
async def security_logs(request: Request):
    return await _record_list(["endpoint_security", "network_security"], request)


@router.post("/analysislog/networksecurity/list")
async def network_security_logs(request: Request):
    return await _record_list("network_security", request)


async def _record_list(kinds: str | list[str], request: Request):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    try:
        return _page(get_repository().list_records(kinds, obj), obj)
    except (TypeError, ValueError) as exc:
        return _error(f"invalid query parameter: {exc}")


@router.post("/whitelists/list")
async def list_whitelists(request: Request):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    try:
        return _page(get_repository().list_whitelists(obj), obj)
    except (TypeError, ValueError) as exc:
        return _error(f"invalid query parameter: {exc}")


@router.post("/whitelists")
async def create_whitelist(request: Request):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    return responses.ok(get_repository().save_whitelist(obj))


@router.put("/whitelists/{white_id}")
async def update_whitelist(white_id: str, request: Request):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    return responses.ok(get_repository().save_whitelist(obj, white_id))


@router.put("/whitelists/{white_id}/status")
async def update_whitelist_status(white_id: str, request: Request):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    if "status" not in obj:
        return _error("status is required")
    if not get_repository().set_whitelist_status(white_id, obj["status"]):
        return _error("whitelist not found", 404)
    return responses.ok({"whiteId": white_id, "status": obj["status"]})


@router.delete("/whitelists")
async def delete_whitelists(request: Request):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    ids = obj.get("whiteIds", obj.get("ids", []))
    if not isinstance(ids, list) or not ids:
        return _error("whiteIds is required")
    count = get_repository().delete_whitelists([str(item) for item in ids])
    return responses.ok({"total": len(ids), "succeededNum": count})


@router.post("/responses/blockiprule/network")
async def block_network(request: Request):
    return await _block(request, "network")


@router.post("/responses/blockiprule/endpoint")
async def block_endpoint(request: Request):
    return await _block(request, "endpoint")


async def _block(request: Request, side: str):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    return responses.ok(get_repository().create_block_rule(obj, side))


@router.post("/responses/blockiprule/unblock")
async def unblock(request: Request):
    return await _set_block(request, "UNBLOCKED")


@router.post("/responses/blockiprule/reblock")
async def reblock(request: Request):
    return await _set_block(request, "BLOCKED")


async def _set_block(request: Request, status: str):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    rule_id = str(obj.get("ruleId") or "")
    if not rule_id:
        return _error("ruleId is required")
    if not get_repository().set_block_status(rule_id, status):
        return _error("block rule not found", 404)
    return responses.ok({"ruleId": rule_id, "status": status})


@router.post("/responses/blockiprule/list")
async def list_blocks(request: Request):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    return _page(get_repository().list_block_rules(obj), obj)


@router.post("/responses/blockiprule/detail")
async def block_detail(request: Request):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    items, _ = get_repository().list_block_rules({"page": 1, "pageSize": 500})
    item = next((item for item in items if item.get("ruleId") == obj.get("ruleId")), None)
    return responses.ok(item) if item else _error("block rule not found", 404)


@router.post("/responses/virusscantask")
async def create_virus_scan(request: Request):
    obj = await _body(request)
    if isinstance(obj, JSONResponse):
        return obj
    if not isinstance(obj.get("devices"), list) or not obj["devices"]:
        return _error("devices is required")
    task = get_repository().create_virus_task(obj)
    return responses.ok({"taskId": task["taskId"]})


@router.get("/responses/virusscantask/{task_id}")
async def get_virus_scan(task_id: str):
    task = get_repository().get_virus_task(task_id)
    return responses.ok(task) if task else _error("virus scan task not found", 404)
