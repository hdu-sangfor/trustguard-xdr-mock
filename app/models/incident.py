# -*- coding: utf-8 -*-
"""安全事件模型（双层：外层包装 + data 层）。

依据：安全事件规范v1.17 + 数据格式说明。外层 type=INCIDENT/update-incident。
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .common import CoercedInt, OptionalInt


class IncidentData(BaseModel):
    model_config = ConfigDict(extra="allow")

    # 标准
    uuId: str | None = None
    v: int | None = None  # 规范必填，样例缺失，放宽
    tenant: str
    customer: str | None = None
    logSampled: OptionalInt = None
    logTraceInfo: str | None = None
    startCloudTs: int | None = None
    endCloudTs: int | None = None

    # 设备/数据来源
    devices: list | None = None
    alertIds: list[str] | None = None
    dataSource: list[str] | None = None
    devUId: list[int] | int | None = None
    hostIp: str | None = None
    agentId: str | None = None
    groupId: str | None = None
    groupMapFlag: OptionalInt = None
    groupMapReference: str | None = None

    # 资产
    assetId: str | None = None
    regionId: str | None = None
    relateAssetType: OptionalInt = None

    # 时间
    startTimestamp: int | None = None
    endTimestamp: int | None = None
    occurTimestamp: int | None = None
    timeRegion: OptionalInt = None
    uploadTimestamp: int | None = None
    uploadTime: str | None = None
    updateTime: str | None = None
    startTime: str | None = None
    endTime: str | None = None

    # 事件基础
    attackState: OptionalInt = None
    name: str | None = None
    description: str | None = None
    riskTag: list[str] | None = None
    recommendation: str | None = None
    msg: str | None = None

    # 等级
    riskLevel: OptionalInt = None
    severity: CoercedInt | None = None
    confidence: CoercedInt | None = None

    # 事件分类（样例实证为 int，规范定义为 string 编码，放宽为 str|int）
    threatClass: str | int | None = None
    threatType: str | int | None = None

    # 事件规则
    eventRuleId: str | None = None
    eventEngine: list | None = None

    # 处置
    dealStatus: OptionalInt = None
    responseAction: list | None = None
    dealMsg: list | None = None
    detectionStatus: OptionalInt = None

    # XDR 业务
    processChain: str | dict | None = None
    attackStory: Any = None  # 样例类型不一，放宽
    rootCauseAnalysis: Any = None
    rawProofData: str | dict | None = None
    threatDefine: list[int] | None = None
    combineType: OptionalInt = None
    alertTag: dict | None = None


class IncidentRecord(BaseModel):
    """安全事件外层包装。"""
    model_config = ConfigDict(extra="allow")

    sendTime: int
    tenant: str
    type: str  # INCIDENT / update-incident
    version: str | int | None = None
    data: IncidentData
