# -*- coding: utf-8 -*-
"""模型注册：导入即注册到 registry。"""
from .registry import register
from .dns_log import DnsLog
from .network_security import NetworkSecurityLog
from .endpoint_security import EndpointSecurityLog
from .endpoint_behavior import EndpointBehaviorLog
from .incident import IncidentRecord
from .alert import AlertRecord

# 规范键 → 顶层模型（外层包装或单层记录）
register("DNS日志", DnsLog)
register("网络安全日志", NetworkSecurityLog)
register("端点安全日志", EndpointSecurityLog)
register("终端行为日志", EndpointBehaviorLog)
register("安全事件", IncidentRecord)
register("安全告警", AlertRecord)
