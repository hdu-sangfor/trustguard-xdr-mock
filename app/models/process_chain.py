# -*- coding: utf-8 -*-
"""共享 processChain 结构（端点/事件/告警复用）。

依据：端点安全日志规范v1.24 中的 processChain 字段定义。
结构较复杂（edges/nodes/alertDetails），此处用宽松嵌套模型校验关键字段，
内部 nodeInfo 按 node type 变化，以 dict 容纳。
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .common import CoercedInt


class ChainEdge(BaseModel):
    model_config = ConfigDict(extra="allow")
    edgeId: str | None = None
    srcNodeId: str | None = None
    dstNodeId: str | None = None
    type: CoercedInt | None = None  # 行为类型 0-34,100
    triggerTime: int | None = None
    alertId: str | None = None
    ruleIds: list | None = None
    subtype: CoercedInt | None = None  # 注入类型 0-10


class ChainNode(BaseModel):
    model_config = ConfigDict(extra="allow")
    nodeId: str | None = None
    type: CoercedInt | None = None
    updateTime: int | None = None
    nodeInfo: dict | None = None
    isWhite: bool | None = None


class AlertDetailRule(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str | None = None
    name: str | None = None
    riskTag: list | None = None
    confidence: CoercedInt | None = None
    threatClass: CoercedInt | None = None
    threatType: CoercedInt | None = None
    threatSubType: CoercedInt | None = None


class AlertDetail(BaseModel):
    model_config = ConfigDict(extra="allow")
    aggAlertId: str | None = None
    alertId: str | None = None
    alertName: str | None = None
    alertType: CoercedInt | None = None  # 0-15
    alertLevel: CoercedInt | None = None  # 0-5
    foundTime: int | None = None
    recentTime: int | None = None
    count: CoercedInt | None = None
    rules: list[AlertDetailRule] | None = None
    alertScore: CoercedInt | None = None


class ChainInfo(BaseModel):
    model_config = ConfigDict(extra="allow")
    edges: list[ChainEdge] | None = None
    nodes: list[ChainNode] | None = None


class ProcessChain(BaseModel):
    model_config = ConfigDict(extra="allow")
    source: str | None = None  # EDR / CWPP
    agentId: str | None = None
    hostIps: list[str] | None = None
    chainInfo: ChainInfo | None = None
    alertDetails: list[AlertDetail] | None = None
    highlightNodelist: list | None = None
