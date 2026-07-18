"""场景注册表。"""
from __future__ import annotations

from . import false_positive_powershell

_BUILDERS = {false_positive_powershell.SCENARIO_ID: false_positive_powershell.build}


def available_scenarios() -> list[str]:
    return sorted(_BUILDERS)


def build_scenario(scenario_id: str, now: int) -> dict:
    builder = _BUILDERS.get(scenario_id)
    if builder is None:
        raise KeyError(scenario_id)
    return builder(now)
