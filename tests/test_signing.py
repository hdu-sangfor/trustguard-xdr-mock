# -*- coding: utf-8 -*-
"""签名互通测试：mock 签名器与原系统 SDK 字节级一致 + 服务端校验端到端。"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from app.config import data_root  # noqa: E402

# 原 SDK 与样例数据同属 xdr-api-data-specs，随 DataOpenDocument 一起定位，
# 因此支持 XDR_DATA_ROOT 覆盖（CI/容器场景）。
_OPENAPI = data_root().parent / "OpenAPIDocument" / "python" / "authCodeDemo"
sys.path.insert(0, str(_OPENAPI))

from aksk_py3 import Signature as OrigSig  # noqa: E402

from app.signing.signer import Signature as MockSig  # noqa: E402
from app.signing import canonical as C  # noqa: E402

AK = "test_ak_0001"
SK = "test_sk_0001_secret"
SD = "20240101T120000Z"


def _orig_sign(method, url, headers, body_str, sign_date):
    """用原 SDK 签名，返回 Authorization。"""
    class Req:
        pass
    r = Req()
    r.method = method
    r.url = url
    r.headers = dict(headers)
    r.params = {}
    r.data = body_str
    r.json = None
    r.headers[C.SIGN_DATE_KEY] = sign_date
    OrigSig(ak=AK, sk=SK).signature(r)
    return r.headers["Authorization"]


def test_post_signature_matches_original():
    url = "https://10.10.10.10/api/xdr/v1/assets/list"
    body = json.dumps({"page": 1, "pageSize": 10})
    mock = MockSig(ak=AK, sk=SK).sign_headers(
        "POST", url, headers={"content-type": "application/json"},
        body=body, sign_date=SD,
    )
    orig = _orig_sign("POST", url, {"content-type": "application/json"}, body, SD)
    assert mock["Authorization"] == orig


def test_get_with_query_matches_original():
    url = "https://10.10.10.10/api/xdr/v1/assets/department"
    mock = MockSig(ak=AK, sk=SK).sign_headers(
        "GET", url + "?test=test&page=1",
        headers={"content-type": "application/json"}, body=None, sign_date=SD,
    )
    # 原 SDK 用 params dict
    class Req:
        pass
    r = Req()
    r.method = "GET"; r.url = url
    r.headers = {"content-type": "application/json"}
    r.headers[C.SIGN_DATE_KEY] = SD
    r.params = {"test": "test", "page": 1}
    r.data = None; r.json = None
    OrigSig(ak=AK, sk=SK).signature(r)
    assert mock["Authorization"] == r.headers["Authorization"]


def test_empty_body_payload_hash():
    assert C.payload_transform(b"") == C.EMPTY_PAYLOAD_HASH
    assert C.EMPTY_PAYLOAD_HASH == (
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    )


def test_payload_signed_byte_sort():
    # 含 >=0x80 字节：有符号排序应把 0x80-0xFF 排在 0x00-0x7F 前
    # bytes [0x01, 0xFF] → 有符号 [-1, 1] → 排序后 [0xFF, 0x01]
    b = bytes([0x01, 0xFF, 0x20])  # 0x20 空格会被移除
    # 排序后去空格: [0xFF, 0x01]
    assert C.payload_transform(b) == C.sha256_hex_upper(bytes([0xFF, 0x01]))


def test_parse_authorization_algorithm_case():
    # Go 用 Algorithm=（大写 A），Python/Java 用 algorithm=
    go = "Algorithm=HMAC-SHA256, Access=ak1, SignedHeaders=a;b, Signature=ABCD"
    parts = C.parse_authorization(go)
    assert parts["algorithm"] == "HMAC-SHA256"
    assert parts[C.ACCESS] == "ak1"
    assert parts[C.SIGNED_HEADERS] == "a;b"
    assert parts[C.SIGNATURE] == "ABCD"


def test_end_to_end_verify():
    """带签名请求经 FastAPI 校验通过。"""
    from fastapi.testclient import TestClient
    from app.main import app
    sig = MockSig(ak=AK, sk=SK)
    client = TestClient(app)
    sd = datetime.now().strftime("%Y%m%dT%H%M%SZ")
    h = sig.sign_headers(
        "GET", "http://testserver/api/xdr/v1/alerts/list?page=1&pageSize=5",
        headers={"content-type": "application/json"}, body=None, sign_date=sd,
    )
    r = client.get("/api/xdr/v1/alerts/list?page=1&pageSize=5", headers=h)
    assert r.status_code == 200


def test_end_to_end_bad_signature_rejected():
    from fastapi.testclient import TestClient
    from app.main import app
    sig = MockSig(ak=AK, sk=SK)
    client = TestClient(app)
    sd = datetime.now().strftime("%Y%m%dT%H%M%SZ")
    h = sig.sign_headers(
        "GET", "http://testserver/api/xdr/v1/alerts/list",
        headers={"content-type": "application/json"}, body=None, sign_date=sd,
    )
    h["Authorization"] = h["Authorization"][:-4] + "XXXX"
    r = client.get("/api/xdr/v1/alerts/list", headers=h)
    assert r.status_code == 401


def test_end_to_end_no_signature_rejected():
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    r = client.get("/api/xdr/v1/alerts/list")
    assert r.status_code == 401
