"""Tests for safety controls — scope guard, kill-switch."""

import pytest

from ransomemu.core.config import RansomEmuConfig
from ransomemu.core.safety import KillSwitch, ScopeGuard


class TestScopeGuard:
    def test_allows_in_scope(self):
        cfg = RansomEmuConfig()
        cfg.scope.allowed_subnets = ["192.168.1.0/24"]
        guard = ScopeGuard(cfg)
        assert guard.is_allowed("192.168.1.10") is True

    def test_blocks_out_of_scope(self):
        cfg = RansomEmuConfig()
        cfg.scope.allowed_subnets = ["192.168.1.0/24"]
        guard = ScopeGuard(cfg)
        assert guard.is_allowed("10.0.0.1") is False

    def test_blocks_excluded_host(self):
        cfg = RansomEmuConfig()
        cfg.scope.allowed_subnets = ["192.168.1.0/24"]
        cfg.scope.excluded_hosts = ["192.168.1.1"]
        guard = ScopeGuard(cfg)
        assert guard.is_allowed("192.168.1.1") is False

    def test_empty_scope_blocks_all(self):
        cfg = RansomEmuConfig()
        cfg.scope.allowed_subnets = []
        guard = ScopeGuard(cfg)
        assert guard.is_allowed("192.168.1.10") is False

    def test_check_raises_on_violation(self):
        cfg = RansomEmuConfig()
        cfg.scope.allowed_subnets = ["10.0.0.0/8"]
        guard = ScopeGuard(cfg)
        with pytest.raises(PermissionError):
            guard.check("192.168.1.1")


class TestKillSwitch:
    def test_arm_and_check(self):
        KillSwitch.arm()
        assert KillSwitch.is_triggered() is False

    def test_trigger(self):
        KillSwitch.arm()
        KillSwitch.trigger()
        assert KillSwitch.is_triggered() is True
        # Cleanup
        KillSwitch.arm()

    def test_check_raises_when_triggered(self):
        KillSwitch.arm()
        KillSwitch.trigger()
        with pytest.raises(SystemExit):
            KillSwitch.check()
        # Cleanup
        KillSwitch.arm()
