# -*- coding: utf-8 -*-
"""状态接口、三层边界和关联误报场景的端到端测试。"""
from __future__ import annotations

import json
from datetime import datetime

from fastapi.testclient import TestClient

from app.main import app
from app.config import data_root
from app.signing.signer import Signature

AK = "test_ak_0001"
SK = "test_sk_0001_secret"
ADMIN_TOKEN = "mock_admin_token_change_me"
client = TestClient(app)
sig = Signature(ak=AK, sk=SK)


def _request(method: str, path: str, payload=None, *, admin: bool = False):
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = sig.sign_headers(
        method,
        f"http://testserver{path}",
        headers={"content-type": "application/json"},
        body=body,
        sign_date=datetime.now().strftime("%Y%m%dT%H%M%SZ"),
    )
    if admin:
        headers["X-Mock-Admin-Token"] = ADMIN_TOKEN
    return client.request(method, path, content=body, headers=headers)


def _seed_powershell():
    _request("POST", "/mock/v1/scenarios:reset", admin=True)
    response = _request(
        "POST", "/mock/v1/scenarios/false-positive-powershell-001:seed", admin=True
    )
    assert response.status_code == 200
    return response.json()["data"]


def test_implemented_official_paths_exist_in_bundled_vendor_openapi():
    html_path = data_root().parent / "OpenAPIDocument" / "深信服XDR平台接口开放列表.html"
    source = html_path.read_text(encoding="utf-8", errors="ignore").replace(r"\/", "/")
    official_uris = {
        "/api/xdr/v1/alerts/list",
        "/api/xdr/v1/alerts/:uuid/proof",
        "/api/xdr/v1/alerts/dealstatus",
        "/api/xdr/v1/incidents/list",
        "/api/xdr/v1/incidents/:uuid/proof",
        "/api/xdr/v1/incidents/dealstatus",
        "/api/xdr/v1/securitylog/list",
        "/api/xdr/v1/analysislog/networksecurity/list",
        "/api/xdr/v1/assets/list",
        "/api/xdr/v1/whitelists/list",
        "/api/xdr/v1/whitelists",
        "/api/xdr/v1/whitelists/:id",
        "/api/xdr/v1/whitelists/:id/status",
        "/api/xdr/v1/responses/blockiprule/network",
        "/api/xdr/v1/responses/virusscantask",
        "/api/xdr/v1/responses/virusscantask/:taskId",
    }
    for uri in official_uris:
        assert f'"apiURI":"{uri}"' in source, f"not found in vendor OpenAPI: {uri}"

    exposed = client.get("/openapi.json").json()["paths"]
    assert "/api/xdr/v1/responses/virusscantask" in exposed
    assert "/api/xdr/v1/response/virusscantask" not in exposed
    assert "get" not in exposed["/api/xdr/v1/alerts/list"]  # 旧 GET 入口不冒充官方接口
    assert (
        exposed["/api/trustguard-mock/v1/query/{data_type}"]["post"]["x-mock-extension"]
        is True
    )
    assert exposed["/mock/v1/scenarios"]["get"]["x-mock-admin"] is True


def test_mock_admin_requires_separate_token_even_with_valid_signature():
    response = _request("GET", "/mock/v1/scenarios")
    assert response.status_code == 403
    assert _request("GET", "/mock/v1/scenarios", admin=True).status_code == 200


def test_correlated_scenario_is_queryable_without_exposing_ground_truth_to_agent():
    seeded = _seed_powershell()
    assert seeded == {
        "scenarioId": "false-positive-powershell-001",
        "records": 3,
        "assets": 1,
        "whitelists": 1,
    }

    response = _request(
        "POST",
        "/api/xdr/v1/alerts/list",
        {"page": 1, "pageSize": 10, "uuIds": ["alert-fp-powershell-001"]},
    )
    data = response.json()["data"]
    assert data["item"] == data["list"]
    assert data["item"][0]["logIds"] == ["endpoint-log-001", "endpoint-log-002"]

    proof = _request(
        "GET", "/api/xdr/v1/alerts/alert-fp-powershell-001/proof"
    ).json()["data"]
    assert proof["proof"]["logIds"] == ["endpoint-log-001", "endpoint-log-002"]

    asset = _request(
        "POST", "/api/xdr/v1/assets/list", {"assetIds": ["17820"]}
    ).json()["data"]["item"][0]
    assert asset["hostName"] == "ops-jump-01"

    whitelist = _request(
        "POST", "/api/xdr/v1/whitelists/list", {"keyword": "PowerShell"}
    ).json()["data"]["item"][0]
    assert whitelist["whiteId"] == "WL-PS-001"
    assert "已审批" in whitelist["reason"]

    response = _request(
        "POST",
        "/api/trustguard-mock/v1/query/endpoint-security",
        {"page": 1, "pageSize": 10, "assetIds": ["17820"]},
    )
    assert response.json()["x-mock-extension"] is True
    assert {item["uuId"] for item in response.json()["data"]["item"]} >= {
        "endpoint-log-001",
        "endpoint-log-002",
    }

    # 预期答案只通过受管控的测试接口返回，不混入 Agent 查询结果。
    truth = _request(
        "GET",
        "/mock/v1/scenarios/false-positive-powershell-001/ground-truth",
        admin=True,
    ).json()["data"]
    assert truth["expectedVerdict"] == "false_positive"
    assert truth["approval"]["ticketId"] == "CHG-2026-0718-001"


def test_alert_deal_status_is_persistent():
    _seed_powershell()
    response = _request(
        "POST",
        "/api/xdr/v1/alerts/dealstatus",
        {
            "uuIds": ["alert-fp-powershell-001"],
            "dealStatus": 2,
            "dealComment": "Agent 判定为已审批运维误报",
        },
    )
    assert response.json()["data"] == {"total": 1, "succeededNum": 1}
    queried = _request(
        "POST",
        "/api/xdr/v1/alerts/list",
        {"uuIds": ["alert-fp-powershell-001"], "page": 1, "pageSize": 10},
    ).json()["data"]["item"][0]
    assert queried["dealStatus"] == 2
    assert queried["dealComment"] == "Agent 判定为已审批运维误报"


def test_whitelist_match_uses_mock_extension_not_fake_official_endpoint():
    _seed_powershell()
    response = _request(
        "POST",
        "/api/trustguard-mock/v1/query/whitelist-match",
        {
            "hostIp": "192.168.2.15",
            "filePath": r"C:\Ops\approved_inventory.ps1",
            "userName": r"CORP\ops-automation",
        },
    )
    assert [item["whiteId"] for item in response.json()["data"]["matched"]] == ["WL-PS-001"]

    # 官方文档没有 /whitelists/match；避免让 Agent 误以为厂商提供该接口。
    fake_path = "/api/xdr/v1/whitelists/match"
    assert _request("POST", fake_path, {}).status_code in {404, 405}


def test_official_whitelist_crud_and_delete_body_signature():
    created = _request(
        "POST",
        "/api/xdr/v1/whitelists",
        {"name": "temporary-test-rule", "ruleList": [{"value": "unit-test"}]},
    ).json()["data"]
    white_id = created["whiteId"]

    status = _request(
        "PUT", f"/api/xdr/v1/whitelists/{white_id}/status", {"status": 0}
    )
    assert status.status_code == 200

    deleted = _request("DELETE", "/api/xdr/v1/whitelists", {"whiteIds": [white_id]})
    assert deleted.status_code == 200
    assert deleted.json()["data"]["succeededNum"] == 1


def test_asset_state_and_response_task_lifecycle():
    asset = {
        "assetId": "TEST-ASSET-001",
        "hostIp": "10.250.0.10",
        "name": "temporary-test-host",
    }
    assert _request("PUT", "/api/xdr/v1/assets/list", {"assets": [asset]}).status_code == 200
    queried = _request(
        "POST", "/api/xdr/v1/assets/list", {"assetIds": ["TEST-ASSET-001"]}
    ).json()["data"]
    assert queried["total"] == 1

    task_id = _request(
        "POST",
        "/api/xdr/v1/responses/virusscantask",
        {"scanType": 1, "scanMode": 1, "devices": ["TEST-ASSET-001"]},
    ).json()["data"]["taskId"]
    assert _request(
        "GET", f"/api/xdr/v1/responses/virusscantask/{task_id}"
    ).json()["data"]["status"] in {"CREATED", "RUNNING"}
    _request("POST", "/mock/v1/clock:advance", {"seconds": 3}, admin=True)
    assert _request(
        "GET", f"/api/xdr/v1/responses/virusscantask/{task_id}"
    ).json()["data"]["status"] == "SUCCESS"

    deleted = _request("DELETE", "/api/xdr/v1/assets/list", {"assetIds": ["TEST-ASSET-001"]})
    assert deleted.json()["data"]["succeededNum"] == 1
