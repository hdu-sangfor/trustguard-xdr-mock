# -*- coding: utf-8 -*-
"""校验器测试：样例回灌（全过）+ 反例检测（拒绝）。"""
import copy
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from app.validators.registry import validate_record  # noqa: E402

_DATA = (
    _ROOT.parent
    / "trustguard-docs"
    / "xdr-api-data-specs"
    / "DataOpenDocument"
)

SPECS = {
    "DNS日志": "DNS日志规范/DNS日志样例数据.txt",
    "网络安全日志": "网络安全日志规范/网络安全日志样例数据.txt",
    "端点安全日志": "端点安全日志规范/端点安全日志样例数据.txt",
    "终端行为日志": "终端行为日志规范/终端行为日志样例数据.txt",
    "安全事件": "安全事件规范/安全事件样例数据.txt",
    "安全告警": "安全告警规范/安全告警样例数据.txt",
}


def _load(spec_key):
    path = _DATA / SPECS[spec_key]
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


def test_all_samples_pass():
    """六份样例全部校验通过（warning 允许，error 为 0）。"""
    total = 0
    for spec_key in SPECS:
        for rec in _load(spec_key):
            rep = validate_record(spec_key, rec)
            assert rep["valid"], (
                f"{spec_key} 样例校验失败: {rep['errors']}"
            )
            total += 1
    assert total >= 60, f"样例数过少: {total}"


def test_missing_required_rejected():
    base = _load("DNS日志")[0]
    bad = copy.deepcopy(base)
    del bad["srcIp"]
    rep = validate_record("DNS日志", bad)
    assert not rep["valid"]
    assert any(e["path"] == "srcIp" for e in rep["errors"])


def test_invalid_enum_rejected():
    base = _load("安全告警")[0]
    for val in (9, 99):
        bad = copy.deepcopy(base)
        bad["data"]["attackState"] = val
        rep = validate_record("安全告警", bad)
        assert not rep["valid"], f"attackState={val} 应被拒绝"
        assert any(e["path"] == "attackState" for e in rep["errors"])

    bad = copy.deepcopy(base)
    bad["data"]["dealStatus"] = 999
    rep = validate_record("安全告警", bad)
    assert not rep["valid"]
    assert any(e["path"] == "dealStatus" for e in rep["errors"])


def test_wrong_type_rejected():
    base = _load("DNS日志")[0]
    bad = copy.deepcopy(base)
    bad["srcPort"] = "not-a-port"
    rep = validate_record("DNS日志", bad)
    assert not rep["valid"]


def test_reversed_logtrace_warns():
    base = _load("DNS日志")[0]
    bad = copy.deepcopy(base)
    # 反序：transfer 在 collect 前
    bad["logTraceInfo"] = (
        '{"appName":"transfer","timestamp":1}|{"appName":"collect","timestamp":2}'
    )
    rep = validate_record("DNS日志", bad)
    # 链路异常记 warning 而非 error（不误杀合法变体）
    assert any(w["code"] == "chain_order" for w in rep["warnings"])


def test_terminal_behavior_no_logtrace():
    """终端行为日志不应有 logTraceInfo。"""
    base = _load("终端行为日志")[0]
    assert "logTraceInfo" not in base
    # 强行加 logTraceInfo 应记 warning
    bad = copy.deepcopy(base)
    bad["logTraceInfo"] = '{"appName":"collect","timestamp":1}'
    rep = validate_record("终端行为日志", bad)
    assert any(w["code"] == "unexpected_logtrace" for w in rep["warnings"])


def test_unknown_spec_and_non_object_rejected():
    rep = validate_record("不存在的规范", {})
    assert rep["valid"] is False
    assert rep["errors"][0]["code"] == "no_model"

    rep = validate_record("DNS日志", [])
    assert rep["valid"] is False
    assert rep["errors"][0]["code"] == "record_type"


def test_validate_strictness_modes(monkeypatch):
    from app import config

    base = _load("网络安全日志")[0]
    cfg = dict(config.get_config())

    monkeypatch.setattr(config, "_CONFIG", {**cfg, "validate_strictness": "normal"})
    normal = validate_record("网络安全日志", base)
    assert normal["valid"] is True
    assert any(w["code"] == "extra_fields" for w in normal["warnings"])

    monkeypatch.setattr(config, "_CONFIG", {**cfg, "validate_strictness": "strict"})
    strict = validate_record("网络安全日志", base)
    assert strict["valid"] is False
    assert any(e["code"] == "extra_fields" for e in strict["errors"])

    bad_enum = copy.deepcopy(_load("安全告警")[0])
    bad_enum["data"]["dealStatus"] = 999
    monkeypatch.setattr(config, "_CONFIG", {**cfg, "validate_strictness": "lenient"})
    lenient = validate_record("安全告警", bad_enum)
    assert lenient["valid"] is True
