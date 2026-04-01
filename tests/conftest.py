"""Shared test fixtures."""

import pytest

from ransomemu.core.config import RansomEmuConfig
from ransomemu.reporting.collector import EventCollector


@pytest.fixture
def config() -> RansomEmuConfig:
    """Create a test configuration with safe defaults."""
    return RansomEmuConfig(
        dry_run=True,
        max_hops=2,
        max_targets=5,
        timeout=10,
    )


@pytest.fixture(autouse=True)
def reset_collector():
    """Reset the EventCollector singleton between tests."""
    EventCollector.reset()
    yield
    EventCollector.reset()
