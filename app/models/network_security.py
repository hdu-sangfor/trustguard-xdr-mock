# -*- coding: utf-8 -*-
"""网络安全日志模型（单层）。

依据：网络安全日志规范v1.21。举证字段族极多，全部 optional（样例中未用的为 null）。
本模型校验公共字段 + 关键枚举；举证字段以 extra="allow" 容纳。
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .common import CoercedInt, OptionalInt
from . import enums as E


class NetworkSecurityLog(BaseModel):
    model_config = ConfigDict(extra="allow")

    # 标准/租户/跟踪
    v: int
    tenant: str
    customer: str | None = None
    logSampled: OptionalInt = None
    logTraceInfo: str | None = None
    cloudTs: int | None = None

    # 时间
    recordTimestamp: int
    uploadTimestamp: int
    insertTimestamp: int | None = None
    recordTime: str
    uploadTime: str

    # 设备
    vendor: str
    productType: str
    productVer: str
    manage: str | None = None
    manageIp: str | None = None
    originProductType: str
    originProductVer: str
    deviceId: str
    deviceIp: str | None = None
    devUId: CoercedInt | None = None
    cascadeType: OptionalInt = None
    uuId: str | None = None
    sessionId: str | None = None

    # 源/目的
    srcIp: str | None = None
    srcPort: CoercedInt | None = None
    srcMac: str | None = None
    srcIpTag: OptionalInt = None
    srcType: OptionalInt = None
    srcSubType: OptionalInt = None
    srcCountry: str | None = None
    srcProvince: str | None = None
    srcCity: str | None = None
    srcAssetId: str | None = None
    srcRegionId: str | None = None

    dstIp: str | None = None
    dstPort: CoercedInt | None = None
    dstMac: str | None = None
    dstIpTag: OptionalInt = None
    dstType: OptionalInt = None
    dstSubType: OptionalInt = None
    dstCountry: str | None = None
    dstProvince: str | None = None
    dstCity: str | None = None
    dstAssetId: str | None = None
    dstRegionId: str | None = None

    # 业务系统映射
    dstMapGroupId: str | None = None
    dstMapGroupFlag: OptionalInt = None
    dstMapGroupReference: str | None = None
    dstAssetGroupId: list[str] | None = None

    # 隧道
    greSrcIp: list[str] | None = None
    greDstIp: list[str] | None = None
    vxlanId: list[int] | None = None
    vlanId: list[int] | None = None
    mplsLabel: list[int] | None = None
    tunnelProtocol: list[str] | None = None

    # 日志分类
    threatClass: OptionalInt = None
    threatType: OptionalInt = None
    threatSubType: OptionalInt = None
    moduleTypeOrigin: OptionalInt = None
    moduleType: str | None = None
    threatTypeCode: str | None = None
    threatSubTypeCode: str | None = None

    # 规则
    reqRuleId: str | None = None
    ruleName: str | None = None
    ruleDescription: str | None = None
    engine: str | None = None
    engineVersion: str | None = None
    engineRuleVersion: str | None = None

    # 协议/状态
    l7Protocol: str | None = None
    l4Protocol: str | None = None
    l3Protocol: str | None = None
    attackState: OptionalInt = None
    white: OptionalInt = None
    action: OptionalInt = None

    # ATT&CK/等级
    tactic: str | None = None
    technique: str | None = None
    severity: CoercedInt | None = None
    confidence: CoercedInt | None = None
    riskLevel: OptionalInt = None

    # 举证/情报/高亮（结构化字段，其余举证字段以 extra 容纳）
    proofType: list[str] | None = None
    proofDescription: str | None = None
    baseContent: str | None = None
    rawMsg: str | None = None
