# -*- coding: utf-8 -*-
"""终端行为日志模型（单层，无 logTraceInfo）。

依据：终端行为日志规范v1.8。样例多为空/哨兵值(-1/-2/9999)，字段大量 optional。
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .common import CoercedInt, OptionalInt


class EndpointBehaviorLog(BaseModel):
    model_config = ConfigDict(extra="allow")

    # 标准/租户（无 logTraceInfo）
    v: int
    tenant: str | int  # 规范为 int，样例为 string
    customer: str | None = None
    logSampled: OptionalInt = None
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
    uuId: str | None = None

    # ZTA 身份
    actorId: str | None = None
    actorSessionId: str | None = None

    # 主机
    hostIp: str | None = None
    hostName: str | None = None
    hostMac: str | None = None
    hostOs: str | None = None
    hostOsVersion: str | None = None
    hostOsProductType: OptionalInt = None

    # 容器/资产
    assetId: str | None = None
    regionId: str | None = None
    relateAssetType: OptionalInt = None

    # 进程链关联
    processChainUuid: str | None = None
    rootProcessNodeIds: str | None = None
    processChainEdgeId: str | None = None
    processChainSrcId: str | None = None
    processChainDstId: str | None = None
    eventId: CoercedInt | None = None

    # 进程信息
    pId: CoercedInt | None = None
    pName: str | None = None
    pGuid: str | None = None
    pFilePath: str | None = None
    pMd5: str | None = None
    pSha256: str | None = None
    pCommand: str | None = None
    pStartTime: int | None = None
    pExitCode: OptionalInt | None = None

    # 父进程
    ppId: CoercedInt | None = None
    ppName: str | None = None
    ppGuid: str | None = None
    ppFilePath: str | None = None
    ppMd5: str | None = None

    # 网络/注册表/模块/服务/账户等（大量 optional，以 extra 容纳）
    rawMsg: str | None = None
