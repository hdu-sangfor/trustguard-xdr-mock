# -*- coding: utf-8 -*-
"""API 端到端测试：签名校验 + 查询/校验/导出/生成 接口。"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.signing.signer import Signature  # noqa: E402

AK = "test_ak_0001"
SK = "test_sk_0001_secret"

client = TestClient(app)
sig = Signature(ak=AK, sk=SK)


def _sign(method: str, path: str, body=None) -> dict:
    sd = datetime.now().strftime("%Y%m%dT%H%M%SZ")
    url = f"http://testserver{path}"
    body_bytes = None
    if body is not None:
        if isinstance(body, (bytes, bytearray)):
            body_bytes = bytes(body)
        else:
            body_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")
    return sig.sign_headers(
        method, url, headers={"content-type": "application/json"},
        body=body_bytes, sign_date=sd,
    )


def test_health_no_sign():
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert len(data["signDate"]) == 16
    assert data["signDate"].endswith("Z")
    assert "T" in data["serverTime"]
    assert data["serverTimeUtc"].endswith("Z")
    assert isinstance(data["timezoneOffsetSeconds"], int)
    assert r.headers["cache-control"] == "no-store"


def test_query_alerts():
    h = _sign("GET", "/api/xdr/v1/alerts/list?page=1&pageSize=5")
    r = client.get("/api/xdr/v1/alerts/list?page=1&pageSize=5", headers=h)
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["total"] >= 1
    assert len(d["list"]) <= 5


def test_query_generate():
    h = _sign("GET", "/api/xdr/v1/dns/list?generate=true&count=3&page=1&pageSize=10")
    r = client.get("/api/xdr/v1/dns/list?generate=true&count=3&page=1&pageSize=10", headers=h)
    assert r.status_code == 200
    assert r.json()["data"]["total"] == 3


def test_validate_alert():
    from app.generators.loader import load_samples
    s = load_samples("安全告警")[0]
    body = json.dumps(s, ensure_ascii=False).encode("utf-8")
    h = _sign("POST", "/api/xdr/v1/validate/alerts", body=body)
    r = client.post("/api/xdr/v1/validate/alerts", content=body, headers=h)
    assert r.status_code == 200
    rep = r.json()["data"]
    assert rep["valid"] is True


def test_validate_rejects_bad():
    from app.generators.loader import load_samples
    import copy
    s = copy.deepcopy(load_samples("安全告警")[0])
    s["data"]["dealStatus"] = 999  # 非法
    body = json.dumps(s, ensure_ascii=False).encode("utf-8")
    h = _sign("POST", "/api/xdr/v1/validate/alerts", body=body)
    r = client.post("/api/xdr/v1/validate/alerts", content=body, headers=h)
    assert r.status_code == 200
    rep = r.json()["data"]
    assert rep["valid"] is False
    assert any(e["path"] == "dealStatus" for e in rep["errors"])


def test_export_dns():
    h = _sign("GET", "/api/xdr/v1/export/dns?count=3")
    r = client.get("/api/xdr/v1/export/dns?count=3", headers=h)
    assert r.status_code == 200
    lines = [l for l in r.text.splitlines() if l.strip()]
    assert len(lines) == 3
    # 每行是合法 JSON
    json.loads(lines[0])


def test_export_generate():
    h = _sign("GET", "/api/xdr/v1/export/incidents?generate=true&count=5")
    r = client.get("/api/xdr/v1/export/incidents?generate=true&count=5", headers=h)
    assert r.status_code == 200
    lines = [l for l in r.text.splitlines() if l.strip()]
    assert len(lines) == 5


def test_assets_list():
    h = _sign("GET", "/api/xdr/v1/assets/list?page=1&pageSize=10")
    r = client.get("/api/xdr/v1/assets/list?page=1&pageSize=10", headers=h)
    assert r.status_code == 200
    payload = r.json()
    assert payload["code"] == 0
    assert payload["data"]["total"] == 2
    assert payload["data"]["list"][0]["assetId"] == "A12345678"


def test_assets_list_paginates():
    h = _sign("GET", "/api/xdr/v1/assets/list?page=2&pageSize=1")
    r = client.get("/api/xdr/v1/assets/list?page=2&pageSize=1", headers=h)
    assert r.status_code == 200
    assert [item["assetId"] for item in r.json()["data"]["list"]] == ["A12345679"]


def test_official_post_query_routes():
    for path in ("/api/xdr/v1/alerts/list", "/api/xdr/v1/incidents/list"):
        body = json.dumps({"page": 1, "pageSize": 2}).encode("utf-8")
        h = _sign("POST", path, body=body)
        r = client.post(path, content=body, headers=h)
        assert r.status_code == 200
        assert r.json()["code"] == 0
        assert len(r.json()["data"]["list"]) == 2


def test_official_assets_post_query():
    path = "/api/xdr/v1/assets/list"
    body = json.dumps({"page": 1, "pageSize": 10, "assetIds": ["A12345679"]}).encode("utf-8")
    h = _sign("POST", path, body=body)
    r = client.post(path, content=body, headers=h)
    assert r.status_code == 200
    assert [item["assetId"] for item in r.json()["data"]["list"]] == ["A12345679"]


def test_query_rejects_unknown_type_and_reversed_time_range():
    unknown = "/api/xdr/v1/not_a_type/list"
    h = _sign("GET", unknown)
    r = client.get(unknown, headers=h)
    assert r.status_code == 404
    assert r.json()["code"] == 404

    reversed_range = "/api/xdr/v1/dns/list?startTimestamp=20&endTimestamp=10"
    h = _sign("GET", reversed_range)
    r = client.get(reversed_range, headers=h)
    assert r.status_code == 400
    assert r.json()["code"] == 400


def test_validate_rejects_non_object_and_bad_batch_shape():
    path = "/api/xdr/v1/validate/dns"
    body = b"[]"
    h = _sign("POST", path, body=body)
    r = client.post(path, content=body, headers=h)
    assert r.status_code == 400

    batch_path = "/api/xdr/v1/validate/batch/dns"
    body = json.dumps({"records": [None]}).encode("utf-8")
    h = _sign("POST", batch_path, body=body)
    r = client.post(batch_path, content=body, headers=h)
    assert r.status_code == 400


def test_no_sign_rejected():
    r = client.get("/api/xdr/v1/alerts/list")
    assert r.status_code == 401
