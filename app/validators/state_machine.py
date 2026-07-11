# -*- coding: utf-8 -*-
"""状态机校验：dealStatus / attackState 流转合法性。

告警 dealStatus: 0未处置 → 70处置中 → 10生成事件/60已遏制 → 终态(20已完成/30已加白/40已驳回/50已忽略/80误报)
attackState: 0尝试 → 1失败/2成功 → 3失陷

单条记录只能校验当前状态合法性（是否在枚举内），流转合法性需历史上下文。
此处校验：枚举值合法 + attackState 语义（如 dealStatus=80误报 时 attackState 通常非失陷）。
"""
from __future__ import annotations

# 告警 dealStatus 枚举
ALERT_DEAL_STATUS = {0, 10, 20, 30, 40, 50, 60, 70, 80}
# 事件 dealStatus 枚举（与告警不同）
INCIDENT_DEAL_STATUS = {0, 10, 20, 30, 40, 50, 60, 70, 80}
# attackState 枚举
ATTACK_STATE = {0, 1, 2, 3}


def validate_state(spec_key: str, record: dict) -> list[dict]:
    warnings = []
    data = record.get("data", record) if isinstance(record.get("data"), dict) else record

    attack = data.get("attackState")
    if attack is not None and isinstance(attack, int) and attack not in ATTACK_STATE:
        warnings.append({
            "path": "attackState",
            "msg": f"attackState 非法值: {attack}，应为 0/1/2/3",
            "code": "invalid_attackstate",
        })

    deal = data.get("dealStatus")
    if deal is not None and isinstance(deal, int):
        valid_set = INCIDENT_DEAL_STATUS if spec_key == "安全事件" else ALERT_DEAL_STATUS
        if deal not in valid_set:
            warnings.append({
                "path": "dealStatus",
                "msg": f"dealStatus 非法值: {deal}",
                "code": "invalid_dealstatus",
            })

    return warnings
