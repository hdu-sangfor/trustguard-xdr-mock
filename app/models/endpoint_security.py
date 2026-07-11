# -*- coding: utf-8 -*-
"""端点安全日志模型（单层）。

依据：终端安全日志规范v1.24。详情字段族按 proofType 出现，全部 optional。
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .common import CoercedInt, OptionalInt
from . import enums as E


class EndpointSecurityLog(BaseModel):
    model_config = ConfigDict(extra="allow")

    # 标准/租户/跟踪
    v: int | None = None  # 规范必填，但样例缺失，放宽
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
    occurTimestamp: int | None = None
    lastTimestamp: int | None = None
    firstTimestamp: int | None = None

    # 设备
    vendor: str
    productType: str
    productVer: str | None = None
    manage: str | None = None
    manageIp: str | None = None
    originProductType: str
    originProductVer: str | None = None
    deviceId: str
    deviceIp: str | None = None
    devUId: CoercedInt | None = None
    cascadeType: OptionalInt = None
    uuId: str | None = None
    incidentId: str | None = None

    # 主机
    hostIp: str | None = None
    hostName: str | None = None
    hostMac: str | None = None
    hostOs: str | None = None
    hostOsProductType: OptionalInt = None

    # 容器/资产
    assetId: str | None = None
    regionId: str | None = None
    relateAssetType: OptionalInt = None

    # 分类/等级/状态
    threatClass: OptionalInt = None
    threatType: OptionalInt = None
    threatSubType: OptionalInt = None
    severity: CoercedInt | None = None
    confidence: CoercedInt | None = None
    riskLevel: OptionalInt = None
    attackState: OptionalInt = None
    white: OptionalInt = None
    action: OptionalInt = None
    hasReported: OptionalInt = None

    # 引擎/规则/举证
    engine: str | None = None
    engineVersion: str | None = None
    engineRuleVersion: str | None = None
    ruleId: str | None = None
    ruleName: str | None = None
    riskTag: list[str] | None = None
    proofType: list[str] | None = None
    proofDescription: str | None = None
    baseContent: str | None = None
    processChain: dict | None = None
    highlight: list | None = None
    rawMsg: str | None = None

    # virus 详情
    virusName: str | None = None
    virusType: str | None = None
    virusFindType: OptionalInt = None
    virusDetectEngine: str | None = None
    virusFirstFindTimestamp: int | None = None

    # file/save 详情
    fileId: str | None = None
    fileName: str | None = None
    fileMd5: str | None = None
    filePath: str | None = None
    fileSize: int | None = None
    fileCreateTime: int | None = None
    fileStatus: OptionalInt = None
    fileState: OptionalInt = None
    fileClass: OptionalInt = None
    fileAttr: OptionalInt = None
    fileFmt: OptionalInt = None

    # webshell 详情
    url: str | None = None
    webshellFindType: OptionalInt = None
    domain: str | None = None
    webshellDomainRoot: str | None = None
