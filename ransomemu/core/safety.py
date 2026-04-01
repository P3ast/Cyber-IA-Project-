"""Safety controls — scope guard, kill-switch, dry-run decorator."""

from __future__ import annotations

import ipaddress
import signal
import threading
from functools import wraps
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from ransomemu.core.logger import get_logger

if TYPE_CHECKING:
    from ransomemu.core.config import RansomEmuConfig

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Kill-switch
# ---------------------------------------------------------------------------

_KILL_FILE = Path("/tmp/ransomemu_kill")


class KillSwitch:
    """Global emergency stop. Triggered by sentinel file or SIGUSR1."""

    _active = threading.Event()

    @classmethod
    def arm(cls) -> None:
        cls._active.clear()
        _KILL_FILE.unlink(missing_ok=True)
        # Register signal handler (Unix only, ignored on Windows)
        try:
            signal.signal(signal.SIGUSR1, lambda *_: cls.trigger())
        except (OSError, AttributeError):
            pass

    @classmethod
    def trigger(cls) -> None:
        logger.critical("🛑 KILL-SWITCH ACTIVATED — all operations stopped")
        cls._active.set()
        _KILL_FILE.touch()

    @classmethod
    def is_triggered(cls) -> bool:
        return cls._active.is_set() or _KILL_FILE.exists()

    @classmethod
    def check(cls) -> None:
        """Raise if kill-switch is active."""
        if cls.is_triggered():
            raise SystemExit("Kill-switch active — aborting.")


# ---------------------------------------------------------------------------
# Scope guard
# ---------------------------------------------------------------------------


class ScopeGuard:
    """Validates that targets are within the authorised scope."""

    def __init__(self, config: RansomEmuConfig) -> None:
        self._networks = [
            ipaddress.ip_network(s, strict=False)
            for s in config.scope.allowed_subnets
        ]
        self._excluded = set(config.scope.excluded_hosts)

    def is_allowed(self, target: str) -> bool:
        if target in self._excluded:
            return False
        if not self._networks:
            # No scope defined → block everything (safe default)
            return False
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            # Hostname — allow if any subnet is defined (DNS resolved later)
            return True
        return any(addr in net for net in self._networks)

    def check(self, target: str) -> None:
        if not self.is_allowed(target):
            raise PermissionError(f"Target {target!r} is outside authorised scope")


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------


def scope_check(func: Callable) -> Callable:
    """Decorator that validates the 'target' kwarg against scope before execution."""

    @wraps(func)
    def wrapper(self, *args, target: str, **kwargs):
        KillSwitch.check()
        if hasattr(self, "_scope_guard"):
            self._scope_guard.check(target)
        if hasattr(self, "_config") and self._config.dry_run:
            logger.info(f"[DRY-RUN] Would execute {func.__name__} on {target}")
            return {"status": "dry-run", "target": target, "action": func.__name__}
        return func(self, *args, target=target, **kwargs)

    return wrapper
