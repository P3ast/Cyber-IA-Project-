"""Abstract base class for lateral movement modules."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ransomemu.core.config import RansomEmuConfig
from ransomemu.core.logger import get_logger
from ransomemu.core.safety import KillSwitch, ScopeGuard

logger = get_logger(__name__)


@dataclass
class MoveResult:
    """Result of a lateral movement attempt."""

    target: str
    protocol: str
    success: bool
    duration_s: float = 0.0
    output: str = ""
    error: str = ""
    files_marked: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "protocol": self.protocol,
            "success": self.success,
            "duration_s": round(self.duration_s, 3),
            "output": self.output,
            "error": self.error,
            "files_marked": self.files_marked,
        }


class LateralMoveBase(ABC):
    """Base class for all lateral movement implementations."""

    protocol: str = "UNKNOWN"

    def __init__(self, config: RansomEmuConfig) -> None:
        self._config = config
        self._scope_guard = ScopeGuard(config)

    def execute(self, target: str, **kwargs) -> MoveResult:
        """Execute lateral movement with safety checks."""
        KillSwitch.check()
        self._scope_guard.check(target)

        if self._config.dry_run:
            logger.info(f"[DRY-RUN] {self.protocol} → {target}")
            return MoveResult(
                target=target,
                protocol=self.protocol,
                success=True,
                output="dry-run: no action taken",
            )

        t0 = time.time()
        try:
            result = self._execute(target, **kwargs)
            result.duration_s = time.time() - t0
            if result.success:
                logger.info(f"✅ {self.protocol} → {target} ({result.duration_s:.1f}s)")
            else:
                logger.warning(f"❌ {self.protocol} → {target}: {result.error}")
            return result
        except Exception as exc:
            duration = time.time() - t0
            logger.error(f"💥 {self.protocol} → {target}: {exc}")
            return MoveResult(
                target=target,
                protocol=self.protocol,
                success=False,
                duration_s=duration,
                error=str(exc),
            )

    @abstractmethod
    def _execute(self, target: str, **kwargs) -> MoveResult:
        """Implement the actual lateral movement logic."""
        ...
