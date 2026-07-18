"""测试会话隔离：保留基础官方样例，清除上次运行遗留的场景数据。"""
from __future__ import annotations

import pytest

from app.repositories import get_repository


@pytest.fixture(scope="session", autouse=True)
def reset_mock_scenarios_for_test_session():
    repository = get_repository()
    repository.reset_scenarios()
    yield
    repository.reset_scenarios()
