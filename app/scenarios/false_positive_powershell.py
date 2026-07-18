# -*- coding: utf-8 -*-
"""已审批运维脚本触发 PowerShell 告警的误报场景。"""
from __future__ import annotations

import copy

from ..generators.loader import load_samples

SCENARIO_ID = "false-positive-powershell-001"


def build(now: int) -> dict:
    candidates = [
        copy.deepcopy(row)
        for row in load_samples("端点安全日志")
        if str(row.get("assetId")) == "17820"
    ]
    if len(candidates) < 2:
        raise RuntimeError("官方端点安全样例中缺少 assetId=17820 的 PowerShell 关联日志")

    log_ids = ["endpoint-log-001", "endpoint-log-002"]
    for index, row in enumerate(candidates[:2]):
        row.update(
            {
                "uuId": log_ids[index],
                "recordTimestamp": now - 180 + index * 60,
                "uploadTimestamp": now - 170 + index * 60,
                "assetId": "17820",
                "hostIp": "192.168.2.15",
                "filePath": r"c:\windows\system32\windowspowershell\v1.0\powershell.exe",
                "processParam": (
                    r"powershell.exe -ExecutionPolicy Bypass "
                    r"-File C:\Ops\approved_inventory.ps1"
                ),
                "severity": 30,
            }
        )

    alert = {
        "uuId": "alert-fp-powershell-001",
        "name": "PowerShell 绕过执行策略执行脚本",
        "description": "终端检测到 PowerShell ExecutionPolicy Bypass 参数",
        "occurTimestamp": now - 60,
        "lastTimestamp": now - 60,
        "uploadTimestamp": now - 50,
        "assetId": "17820",
        "hostAssetId": "17820",
        "hostIp": "192.168.2.15",
        "srcIp": ["192.168.2.15"],
        "dstIp": [],
        "severity": 30,
        "dealStatus": 0,
        "whiteStatus": 1,
        "threatClass": 3,
        "threatType": 3,
        "threatSubType": 1,
        "attackState": 0,
        "attackResult": 0,
        "proofType": 1,
        "logIds": log_ids,
        "recommendation": "核验脚本来源、审批单、签名哈希与执行主机范围",
        "processChain": [
            {
                "processName": "powershell.exe",
                "processParam": (
                    r"-ExecutionPolicy Bypass -File C:\Ops\approved_inventory.ps1"
                ),
                "userName": r"CORP\ops-automation",
            }
        ],
    }
    asset = {
        "assetId": "17820",
        "hostAssetId": "17820",
        "hostIp": "192.168.2.15",
        "ip": "192.168.2.15",
        "name": "ops-jump-01",
        "hostName": "ops-jump-01",
        "branchId": 2,
        "branchName": "运维部",
        "businessId": "OPS-AUTO",
        "importance": "medium",
        "tags": ["运维跳板机", "自动化资产盘点"],
        "owner": "ops-team",
    }
    whitelist = {
        "whiteId": "WL-PS-001",
        "name": "已审批资产盘点 PowerShell 脚本",
        "status": 1,
        "hostIp": "192.168.2.15",
        "isHostAll": False,
        "isUnlimited": False,
        "timeRange": {"start": now - 86400, "end": now + 86400 * 30},
        "ruleList": [
            {"field": "filePath", "operator": "equals", "value": r"C:\Ops\approved_inventory.ps1"},
            {"field": "userName", "operator": "equals", "value": r"CORP\ops-automation"},
            {"field": "changeTicket", "operator": "equals", "value": "CHG-2026-0718-001"},
        ],
        "reason": "运维部已审批的每晚资产盘点任务",
        "creator": "soc-admin",
        "createTime": now - 86400,
        "updateTime": now - 3600,
    }
    ground_truth = {
        "scenarioId": SCENARIO_ID,
        "alertUuid": alert["uuId"],
        "expectedVerdict": "false_positive",
        "expectedConfidenceMin": 0.90,
        "reasonCodes": [
            "APPROVED_CHANGE_TICKET",
            "WHITELIST_EXACT_MATCH",
            "EXPECTED_ASSET_AND_ACCOUNT",
            "NO_MALICIOUS_FOLLOW_UP",
        ],
        "approval": {
            "ticketId": "CHG-2026-0718-001",
            "status": "APPROVED",
            "scriptPath": r"C:\Ops\approved_inventory.ps1",
            "executor": r"CORP\ops-automation",
            "targetAssetIds": ["17820"],
        },
        "expectedAction": "suppress_and_record",
    }
    return {
        "scenarioId": SCENARIO_ID,
        "records": [
            {"kind": "endpoint_security", "payload": candidates[0]},
            {"kind": "endpoint_security", "payload": candidates[1]},
            {"kind": "alerts", "payload": alert},
        ],
        "assets": [asset],
        "whitelists": [whitelist],
        "groundTruth": ground_truth,
    }
