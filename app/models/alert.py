# -*- coding: utf-8 -*-
"""安全告警模型（双层：外层包装 + data 层）。

依据：安全告警规范v1.30 + 数据格式说明。外层含 refreshTime/alertType。
告警源/目的字段多为 array 类型（与日志不同）。
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .common import CoercedInt, OptionalInt


class AlertData(BaseModel):
    model_config = ConfigDict(extra="allow")

    # 标准/租户/跟踪
    uuId: str | None = None
    v: int
    tenant: str
    customer: str | None = None
    logSampled: OptionalInt = None
    logTraceInfo: str | None = None
    startCloudTs: int | None = None
    endCloudTs: int | None = None
    seqId: str | None = None
    devices: list | None = None
    devUId: list[int] | int | None = None
    devUName: list[str] | None = None

    # 日志关联
    logIds: list[str] | None = None
    logs: list | None = None
    logCount: CoercedInt | None = None

    # 主机/业务系统
    hostIp: str | None = None
    agentId: str | None = None
    groupId: str | None = None
    groupMapFlag: OptionalInt = None
    groupMapReference: str | None = None

    # 资产
    assetId: str | None = None
    regionId: str | None = None
    relateAssetType: OptionalInt = None

    # 主体/身份
    subjectType: list[str] | None = None
    xUserUId: str | None = None
    xUserId: str | None = None
    xUserName: str | None = None
    accountId: str | None = None
    accountName: str | None = None

    # 时间
    firstTimestamp: int | None = None
    lastTimestamp: int | None = None
    occurTimestamp: int | None = None
    timeRegion: OptionalInt = None
    uploadTimestamp: int | None = None
    uploadTime: str | None = None

    # 告警基础
    attackState: OptionalInt = None
    name: str | None = None
    description: str | None = None
    recommendation: str | None = None
    riskTag: list[str] | None = None

    # 源/目的（array）
    srcIp: list[str] | None = None
    srcPort: list[int] | None = None
    srcAssetId: list[str] | None = None
    srcIpTag: list[int] | int | None = None
    srcRegionId: list[str] | None = None
    xffClientIp: list[str] | None = None
    xffClientIpTag: OptionalInt = None
    dstIp: list[str] | None = None
    dstPort: list[int] | None = None
    dstAssetId: list[str] | None = None
    dstRegionId: list[str] | None = None
    direction: OptionalInt = None
    xForwardedFor: list[str] | None = None

    # 隧道
    protocol: str | None = None
    greSrcIp: list[str] | None = None
    greDstIp: list[str] | None = None
    vxlanId: list[int] | None = None
    vlanId: list[int] | None = None
    mplsLabel: list[int] | None = None
    tunnelProtocol: list[str] | None = None

    # 等级
    riskLevel: OptionalInt = None
    severity: CoercedInt | None = None
    confidence: CoercedInt | None = None

    # 安全分类
    threatClass: OptionalInt = None
    threatType: OptionalInt = None
    threatSubType: OptionalInt = None

    # 规则
    alertRuleId: str | None = None
    alertEngine: list | None = None
    ruleIds: list[str] | None = None

    # 处置
    dealStatus: OptionalInt = None
    responseAction: list | None = None

    # ATT&CK
    stage: OptionalInt = None
    attckTechnique: list[str] | None = None

    # 举证/情报/聚类/高亮
    proofType: list[str] | None = None
    threatDetail: list | None = None
    clusterId: str | None = None
    highlight: list | None = None
    analysisInfo: str | None = None

    # 业务/XDR
    dealMsg: list | None = None
    pName: list | None = None
    processPathDetails: list | None = None
    proofDescription: str | None = None
    baseContent: str | None = None
    threatDefine: list[int] | None = None
    combineType: OptionalInt = None
    versionDetails: list | None = None
    extensions: str | dict | None = None
    processChain: dict | None = None


class AlertRecord(BaseModel):
    """安全告警外层包装。"""
    model_config = ConfigDict(extra="allow")

    sendTime: int
    tenant: str
    type: str  # ALERT
    version: str | int | None = None
    refreshTime: str | int | None = None
    alertType: str | None = None
    data: AlertData
