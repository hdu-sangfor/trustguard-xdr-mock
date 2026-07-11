# -*- coding: utf-8 -*-
"""DNS 协议审计日志模型（单层，字段在顶层）。

依据：DNS协议审计日志规范v1.11 + 样例数据实证。
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .common import CoercedInt, OptionalInt
from . import enums as E


class DnsLog(BaseModel):
    """DNS 日志（单层）。"""
    model_config = ConfigDict(extra="allow")

    # 标准信息
    v: int = Field(..., description="数据版本")
    tenant: str
    customer: str | None = None
    logSampled: OptionalInt = None
    logTraceInfo: str | None = None
    cloudTs: int | None = None

    # 时间属性
    recordTimestamp: int
    uploadTimestamp: int
    insertTimestamp: int | None = None
    recordTime: str
    uploadTime: str

    # 设备信息
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

    # 日志信息
    uuId: str | None = None
    sessionId: str | None = None

    # 源/目的
    srcIp: str
    srcPort: CoercedInt
    srcMac: str | None = None
    srcIpTag: OptionalInt = None
    srcType: OptionalInt = None
    srcSubType: OptionalInt = None
    srcCountry: str | None = None
    srcProvince: str | None = None
    srcCity: str | None = None
    srcAssetId: str | None = None
    srcRegionId: str | None = None

    dstIp: str
    dstPort: CoercedInt
    dstMac: str | None = None
    dstIpTag: OptionalInt = None
    dstType: OptionalInt = None
    dstSubType: OptionalInt = None
    dstCountry: str | None = None
    dstProvince: str | None = None
    dstCity: str | None = None
    dstAssetId: str | None = None
    dstRegionId: str | None = None

    # 隧道（样例中缺失，optional）
    greSrcIp: list[str] | None = None
    greDstIp: list[str] | None = None
    vxlanId: list[int] | None = None
    vlanId: list[int] | None = None
    mplsLabel: list[int] | None = None
    tunnelProtocol: list[str] | None = None

    # DNS 协议字段
    id: CoercedInt
    qr: CoercedInt = Field(..., description="0请求 1响应")
    opCode: CoercedInt
    aa: CoercedInt
    tc: CoercedInt
    rd: CoercedInt
    ra: CoercedInt
    z: CoercedInt = 0
    ad: CoercedInt
    cd: CoercedInt
    rCode: CoercedInt
    qdCnt: CoercedInt
    anCnt: CoercedInt
    nsCnt: CoercedInt
    arCnt: CoercedInt

    queries: str
    qClasses: str
    qTypes: str
    answers: str | None = None
    ttls: str | None = None
    aTypes: str | None = None
    aClasses: str | None = None
    length: CoercedInt
