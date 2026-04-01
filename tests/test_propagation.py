"""Tests for the propagation engine."""

import pytest
from unittest.mock import MagicMock

from ransomemu.core.config import RansomEmuConfig
from ransomemu.modules.propagation.engine import PropagationEngine
from ransomemu.modules.lateral.base import MoveResult
from ransomemu.reporting.collector import EventCollector


class MockMover:
    def __init__(self, config=None):
        self._config = config
        self.protocol = "SMB"

    def execute(self, target, **kwargs):
        if target == "192.168.1.99":
            return MoveResult(target=target, protocol=self.protocol, success=False, error="Connection refused")
        return MoveResult(target=target, protocol=self.protocol, success=True, output="Mock access")


class TestPropagationEngine:
    @pytest.fixture
    def config(self) -> RansomEmuConfig:
        cfg = RansomEmuConfig(max_hops=2, max_targets=5)
        cfg.scope.allowed_subnets = ["192.168.1.0/24"]
        return cfg

    @pytest.fixture
    def engine(self, config: RansomEmuConfig) -> PropagationEngine:
        EventCollector.reset()
        eng = PropagationEngine(config)
        # Inject mock movers
        eng._movers = {
            "SMB": MockMover(),
            "WinRM": MockMover(),
            "WMI": MockMover(),
        }
        return eng

    def test_bfs_propagation(self, engine: PropagationEngine):
        targets = [
            {"ip": "192.168.1.10", "lateral_protocols": ["SMB"]},
            {"ip": "192.168.1.11", "lateral_protocols": ["WinRM"]},
            {"ip": "10.0.0.1", "lateral_protocols": ["SMB"]},  # Out of scope
            {"ip": "192.168.1.99", "lateral_protocols": ["SMB"]},  # Will fail
        ]
        
        state = engine.run(targets, {"username": "admin", "password": "123"}, strategy="bfs")
        
        assert "192.168.1.10" in state.compromised
        assert "192.168.1.11" in state.compromised
        assert "192.168.1.99" in state.failed
        assert "10.0.0.1" not in state.visited  # Blocked by scope guard

    def test_dfs_propagation(self, engine: PropagationEngine):
        targets = [
            {"ip": "192.168.1.10", "lateral_protocols": ["SMB"]},
            {"ip": "192.168.1.11", "lateral_protocols": ["WinRM"]},
        ]
        
        state = engine.run(targets, {"username": "admin", "password": "123"}, strategy="dfs")
        
        assert len(state.compromised) == 2
        assert "192.168.1.10" in state.compromised

    def test_max_targets_limit(self, engine: PropagationEngine):
        engine._config.max_targets = 2
        targets = [
            {"ip": f"192.168.1.{i}", "lateral_protocols": ["SMB"]} for i in range(10, 15)
        ]
        
        state = engine.run(targets, {}, strategy="bfs")
        
        assert len(state.visited) == 2
        
    def test_event_collection(self, engine: PropagationEngine):
        targets = [
            {"ip": "192.168.1.10", "lateral_protocols": ["SMB"]},
        ]
        
        engine.run(targets, {"username": "admin", "password": "123"}, strategy="bfs")
        
        events = engine._collector.get_all()
        # Should have START, ATTEMPT, RESULT, COMPLETE events
        assert len(events) >= 4
        
        types = [e.event_type for e in events]
        assert "PROPAGATION" in types
        assert "LATERAL_MOVE" in types
