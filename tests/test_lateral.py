"""Tests for lateral movement base class."""

import pytest

from ransomemu.core.config import RansomEmuConfig
from ransomemu.modules.lateral.base import LateralMoveBase, MoveResult


class DummyMover(LateralMoveBase):
    """Concrete implementation for testing."""

    protocol = "TEST"

    def _execute(self, target: str, **kwargs) -> MoveResult:
        return MoveResult(
            target=target,
            protocol=self.protocol,
            success=True,
            output="test-ok",
        )


class FailingMover(LateralMoveBase):
    protocol = "FAIL"

    def _execute(self, target: str, **kwargs) -> MoveResult:
        raise ConnectionError("simulated failure")


class TestLateralMoveBase:
    def test_dry_run_returns_without_executing(self, config: RansomEmuConfig):
        config.dry_run = True
        config.scope.allowed_subnets = ["10.0.0.0/8"]
        mover = DummyMover(config)
        result = mover.execute("10.0.0.1")
        assert result.success is True
        assert "dry-run" in result.output

    def test_scope_violation_raises(self, config: RansomEmuConfig):
        config.scope.allowed_subnets = ["10.0.0.0/8"]
        config.dry_run = False
        mover = DummyMover(config)
        with pytest.raises(PermissionError):
            mover.execute("192.168.1.1")

    def test_exception_returns_failed_result(self, config: RansomEmuConfig):
        config.scope.allowed_subnets = ["10.0.0.0/8"]
        config.dry_run = False
        mover = FailingMover(config)
        result = mover.execute("10.0.0.1")
        assert result.success is False
        assert "simulated failure" in result.error

    def test_move_result_to_dict(self):
        r = MoveResult(target="10.0.0.1", protocol="SMB", success=True, files_marked=3)
        d = r.to_dict()
        assert d["target"] == "10.0.0.1"
        assert d["files_marked"] == 3
