# -*- coding: utf-8 -*-
"""枚举值严格校验。

对记录中的枚举字段检查取值是否在合法集合内。
- 硬枚举（error）：dealStatus/attackState/riskLevel/direction 等业务状态，非法值必须报错
- 软枚举（warning）：threatDefine、终端行为日志的 regTokenType/winHookId 等，
  样例中常见哨兵值(0)或非标准值，偏离记 warning 而非 error

自动适配单层/双层结构（事件/告警在 data 层，其余在顶层）。
"""
from __future__ import annotations

from ..models import enums as E


def _data_layer(record: dict) -> dict:
    if isinstance(record.get("data"), dict):
        return record["data"]
    return record


def _is_empty(v) -> bool:
    return v is None or (isinstance(v, str) and v == "")


def _check_hard(value, valid_set, field, errors):
    """硬枚举：非法值记 error。支持 list（逐元素）。"""
    if _is_empty(value):
        return
    if isinstance(value, list):
        for v in value:
            _check_hard(v, valid_set, field, errors)
        return
    if value not in valid_set:
        errors.append({
            "path": field,
            "msg": f"非法枚举值: {value}，合法集合: {sorted(valid_set) if all(isinstance(x, int) for x in valid_set) else list(valid_set)}",
            "code": "invalid_enum",
            "value": value,
        })


def _check_soft(value, valid_set, field, warnings, sentinels=()):
    """软枚举：非法值记 warning（容忍哨兵值）。"""
    if _is_empty(value):
        return
    if isinstance(value, list):
        for v in value:
            _check_soft(v, valid_set, field, warnings, sentinels)
        return
    if value in valid_set or value in sentinels:
        return
    warnings.append({
        "path": field,
        "msg": f"枚举值偏离规范: {value}（合法集合 {sorted(valid_set) if all(isinstance(x,int) for x in valid_set) else list(valid_set)}）",
        "code": "enum_drift",
        "value": value,
    })


def validate_enums(spec_key: str, record: dict) -> tuple[list[dict], list[dict]]:
    """返回 (errors, warnings)。"""
    errors: list[dict] = []
    warnings: list[dict] = []
    d = _data_layer(record)

    # ---- 硬枚举（通用）----
    _check_hard(d.get("logSampled"), E.LOG_SAMPLED, "logSampled", errors)
    _check_hard(d.get("relateAssetType"), E.RELATE_ASSET_TYPE, "relateAssetType", errors)
    _check_hard(d.get("groupMapFlag"), E.GROUP_MAP_FLAG, "groupMapFlag", errors)
    _check_hard(d.get("hostOsProductType"), E.HOST_OS_PRODUCT_TYPE, "hostOsProductType", errors)
    _check_hard(d.get("attackState"), E.ATTACK_STATE, "attackState", errors)
    _check_hard(d.get("white"), E.WHITE, "white", errors)
    _check_hard(d.get("hasReported"), E.HAS_REPORTED, "hasReported", errors)
    _check_hard(d.get("cascadeType"), E.CASCADE_TYPE, "cascadeType", errors)
    _check_hard(d.get("riskLevel"), E.RISK_LEVEL, "riskLevel", errors)

    for f in ("srcIpTag", "dstIpTag", "xffClientIpTag"):
        _check_hard(d.get(f), E.IP_TAG, f, errors)

    # ---- 各类型特有 ----
    if spec_key == "安全告警":
        _check_hard(d.get("direction"), E.DIRECTION, "direction", errors)
        _check_hard(d.get("stage"), E.STAGE, "stage", errors)
        _check_hard(d.get("combineType"), E.COMBINE_TYPE, "combineType", errors)
        _check_hard(d.get("dealStatus"), E.ALERT_DEAL_STATUS, "dealStatus", errors)
        _check_soft(d.get("threatDefine"), E.THREAT_DEFINE, "threatDefine", warnings)

    if spec_key == "安全事件":
        _check_hard(d.get("combineType"), E.COMBINE_TYPE, "combineType", errors)
        _check_hard(d.get("dealStatus"), E.INCIDENT_DEAL_STATUS, "dealStatus", errors)
        _check_hard(d.get("detectionStatus"), E.DETECTION_STATUS, "detectionStatus", errors)
        # threatClass 样例混用规范编码("0001")与安全日志分类大类数字("208")，软校验
        tc = d.get("threatClass")
        if isinstance(tc, str) and tc.isdigit():
            _check_soft(int(tc), E.SEC_LOG_THREAT_CLASS, "threatClass", warnings)
        elif isinstance(tc, int):
            _check_soft(tc, E.SEC_LOG_THREAT_CLASS, "threatClass", warnings)
        elif isinstance(tc, str):
            _check_hard(tc, E.INCIDENT_THREAT_CLASS, "threatClass", errors)
        _check_soft(d.get("threatDefine"), E.THREAT_DEFINE, "threatDefine", warnings)

    if spec_key == "端点安全日志":
        _check_hard(d.get("action"), E.ACTION_ENDPOINT, "action", errors)
        _check_hard(d.get("virusFindType"), E.VIRUS_FIND_TYPE, "virusFindType", errors)
        _check_hard(d.get("fileStatus"), E.FILE_STATUS, "fileStatus", errors)
        _check_hard(d.get("fileClass"), E.FILE_CLASS, "fileClass", errors)
        _check_soft(d.get("fileState"), E.FILE_STATE, "fileState", warnings, sentinels={0})

    if spec_key == "网络安全日志":
        _check_hard(d.get("action"), E.ACTION_LOG, "action", errors)
        _check_hard(d.get("tcpStartState"), E.TCP_START_STATE, "tcpStartState", errors)
        _check_hard(d.get("tcpSessionState"), E.TCP_SESSION_STATE, "tcpSessionState", errors)

    if spec_key == "DNS日志":
        _check_hard(d.get("opCode"), E.DNS_OPCODE, "opCode", errors)
        for f in ("qr", "aa", "tc", "rd", "ra", "ad", "cd"):
            _check_hard(d.get(f), E.DNS_FLAG, f, errors)

    if spec_key == "终端行为日志":
        # eventId 硬枚举
        _check_hard(d.get("eventId"), E.EVENT_ID, "eventId", errors)
        # 以下字段样例常用 0 哨兵，软枚举
        _check_soft(d.get("regOpType"), E.REG_OP_TYPE, "regOpType", warnings, sentinels={0})
        _check_soft(d.get("linkType"), E.LINK_TYPE, "linkType", warnings, sentinels={0})
        _check_soft(d.get("serviceType"), E.SERVICE_TYPE, "serviceType", warnings, sentinels={0})
        _check_soft(d.get("serviceStatus"), E.SERVICE_STATUS, "serviceStatus", warnings, sentinels={0})
        _check_soft(d.get("connectStatus"), E.CONNECT_STATUS, "connectStatus", warnings, sentinels={0})
        _check_soft(d.get("fileOpStatus"), E.FILE_OP_STATUS, "fileOpStatus", warnings, sentinels={0})
        _check_soft(d.get("regTokenType"), E.REG_TOKEN_TYPE, "regTokenType", warnings, sentinels={0})
        _check_soft(d.get("imagePlace"), E.IMAGE_PLACE, "imagePlace", warnings, sentinels={0})
        _check_soft(d.get("winHookId"), E.WIN_HOOK_ID, "winHookId", warnings, sentinels={0})

    return errors, warnings
