# -*- coding: utf-8 -*-
"""批量导出工具：每行一条 JSON。"""
from __future__ import annotations

import json


def export_to_text(records: list[dict]) -> str:
    """将记录列表导出为每行一条 JSON 的文本（对齐样例文件格式）。"""
    lines = []
    for r in records:
        lines.append(json.dumps(r, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


def export_to_file(records: list[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(export_to_text(records))
