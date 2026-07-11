# -*- coding: utf-8 -*-
"""校验结果聚合。

两层校验：
1. pydantic 字段级（models/）— 类型/必填（extra=allow 容纳规范外字段）
2. 业务规则（validators/）— 枚举/链路/时间/状态机，结果记为 warning（避免误杀合法变体）
   严重违规（非法枚举值）记为 error。

返回 {valid, errors, warnings}。
"""
from __future__ import annotations

from typing import Any

# 导入 models 包触发注册
from .. import models  # noqa: F401
from ..models.registry import get_model
from ..config import get_config


def _safe_jsonable(v):
    """将值转为 JSON 可序列化形式（bytes/异常类型转字符串）。"""
    if v is None:
        return None
    if isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return f"<bytes len={len(v)}>"
    if isinstance(v, (list, tuple)):
        return [_safe_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _safe_jsonable(x) for k, x in v.items()}
    return str(v)


def _strictness() -> str:
    value = str(get_config().get("validate_strictness", "normal")).strip().lower()
    return value if value in {"normal", "strict", "lenient"} else "normal"


def _extra_fields(model_cls, record: dict) -> list[str]:
    """收集顶层和事件/告警 data 层未建模字段。"""
    fields = set(model_cls.model_fields)
    out = [str(key) for key in record if key not in fields]

    data = record.get("data")
    data_field = model_cls.model_fields.get("data")
    data_cls = getattr(data_field, "annotation", None) if data_field is not None else None
    if isinstance(data, dict) and hasattr(data_cls, "model_fields"):
        data_fields = set(data_cls.model_fields)
        out.extend(f"data.{key}" for key in data if key not in data_fields)
    return sorted(out)


def validate_record(spec_key: str, record: dict) -> dict:
    """校验单条记录，返回校验报告。"""
    errors: list[dict] = []
    warnings: list[dict] = []

    if not isinstance(record, dict):
        return {
            "valid": False,
            "errors": [
                {
                    "path": "",
                    "msg": "记录必须是 JSON object",
                    "code": "record_type",
                    "value": _safe_jsonable(record),
                }
            ],
            "warnings": [],
        }

    model_cls = get_model(spec_key)
    if model_cls is None:
        return {
            "valid": False,
            "errors": [{"path": "", "msg": f"未实现的规范: {spec_key}", "code": "no_model"}],
            "warnings": [],
        }

    strictness = _strictness()

    # 第一层：pydantic 字段级（类型/必填）
    from pydantic import ValidationError
    try:
        model_cls.model_validate(record)
    except ValidationError as e:
        for err in e.errors():
            loc = ".".join(str(x) for x in err["loc"])
            # input 值可能不可 JSON 序列化（bytes 等），统一转可序列化形式
            inp = err.get("input")
            inp = _safe_jsonable(inp)
            errors.append({
                "path": loc,
                "msg": err["msg"],
                "code": err.get("type", "validation"),
                "value": inp,
            })
    except Exception as e:
        errors.append({"path": "", "msg": str(e), "code": "exception"})

    extras = _extra_fields(model_cls, record)
    if extras and strictness != "lenient":
        item = {
            "path": "",
            "msg": f"发现 {len(extras)} 个模型外字段",
            "code": "extra_fields",
            "value": extras[:100],
        }
        if strictness == "strict":
            errors.append(item)
        else:
            warnings.append(item)

    # lenient 只检查必填字段和类型，不执行格式与业务规则。
    if strictness == "lenient":
        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}

    # 第二层：业务规则（枚举/链路/时间/状态机）— 总是执行
    from .logtrace import validate_logtrace
    from .time_invariants import validate_time
    from .state_machine import validate_state
    from .enum_check import validate_enums
    from .format_check import validate_formats

    warnings.extend(validate_logtrace(spec_key, record))
    warnings.extend(validate_time(spec_key, record))
    warnings.extend(validate_state(spec_key, record))
    # 枚举校验：硬枚举非法值记 error，软枚举偏离记 warning
    enum_errors, enum_warnings = validate_enums(spec_key, record)
    errors.extend(enum_errors)
    warnings.extend(enum_warnings)
    format_errors, format_warnings = validate_formats(spec_key, record, strictness)
    errors.extend(format_errors)
    warnings.extend(format_warnings)

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
    }
