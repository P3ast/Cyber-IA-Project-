"""Propagation engine — orchestrates automated lateral movement across the network."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from ransomemu.agent.chains import LateralMoveChain, ReconAnalysisChain
from ransomemu.agent.llm_client import LLMClient
from ransomemu.core.config import RansomEmuConfig
from ransomemu.core.logger import get_logger
from ransomemu.core.safety import KillSwitch, ScopeGuard
from ransomemu.modules.lateral.base import LateralMoveBase, MoveResult
from ransomemu.modules.lateral.smb_move import SMBMove
from ransomemu.modules.lateral.winrm_move import WinRMMove
from ransomemu.modules.lateral.wmi_move import WMIMove
from ransomemu.reporting.collector import Event, EventCollector, EventType

logger = get_logger(__name__)


@dataclass
class PropagationState:
    """Tracks the state of the propagation simulation."""

    visited: set[str] = field(default_factory=set)
    compromised: set[str] = field(default_factory=set)
    failed: set[str] = field(default_factory=set)
    hop_count: dict[str, int] = field(default_factory=dict)
    results: list[MoveResult] = field(default_factory=list)
    start_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "visited": list(self.visited),
            "compromised": list(self.compromised),
            "failed": list(self.failed),
            "total_results": len(self.results),
            "duration_s": round(time.time() - self.start_time, 2) if self.start_time else 0,
        }


# Map protocol names to classes
PROTOCOL_MAP: dict[str, type[LateralMoveBase]] = {
    "SMB": SMBMove,
    "WinRM": WinRMMove,
    "WMI": WMIMove,
}


class PropagationEngine:
    """Orchestrates the automated propagation simulation.

    Uses the LLM to decide the optimal protocol per target,
    then executes lateral movement in BFS or DFS order.
    """

    def __init__(
        self,
        config: RansomEmuConfig,
        llm_client: LLMClient | None = None,
        collector: EventCollector | None = None,
    ) -> None:
        self._config = config
        self._scope = ScopeGuard(config)
        self._state = PropagationState()
        self._collector = collector or EventCollector()

        # LLM chains (optional — works without LLM in manual mode)
        self._llm = llm_client
        self._recon_chain = ReconAnalysisChain(llm_client) if llm_client else None
        self._lateral_chain = LateralMoveChain(llm_client) if llm_client else None

        # Lateral move instances
        self._movers = {
            name: cls(config) for name, cls in PROTOCOL_MAP.items()
        }

    def run(
        self,
        targets: list[dict[str, Any]],
        credentials: dict[str, str],
        strategy: str = "bfs",
    ) -> PropagationState:
        """Run the propagation simulation.

        Args:
            targets: List of target dicts with 'ip' and 'lateral_protocols'.
            credentials: Dict with 'username', 'password'/'hashes', 'domain'.
            strategy: 'bfs' (breadth-first) or 'dfs' (depth-first).

        Returns:
            Final PropagationState with all results.
        """
        self._state = PropagationState(start_time=time.time())

        logger.info(
            f"🚀 Starting propagation — strategy={strategy}, "
            f"targets={len(targets)}, max_hops={self._config.max_hops}"
        )

        self._collector.add(Event(
            event_type=EventType.PROPAGATION,
            message=f"Propagation started: {strategy}, {len(targets)} targets",
        ))

        if strategy == "dfs":
            self._run_dfs(targets, credentials, hop=0)
        else:
            self._run_bfs(targets, credentials)

        duration = time.time() - self._state.start_time
        logger.info(
            f"🏁 Propagation complete — "
            f"{len(self._state.compromised)}/{len(targets)} compromised "
            f"in {duration:.1f}s"
        )

        self._collector.add(Event(
            event_type=EventType.PROPAGATION,
            message=(
                f"Propagation complete: {len(self._state.compromised)} compromised, "
                f"{len(self._state.failed)} failed, {duration:.1f}s"
            ),
        ))

        return self._state

    def _run_bfs(
        self,
        targets: list[dict[str, Any]],
        credentials: dict[str, str],
    ) -> None:
        """Breadth-first propagation."""
        queue: deque[tuple[dict, int]] = deque()
        for t in targets[:self._config.max_targets]:
            queue.append((t, 0))

        while queue:
            KillSwitch.check()
            target, hop = queue.popleft()
            ip = target.get("ip", "")

            if ip in self._state.visited:
                continue
            if hop > self._config.max_hops:
                continue
            if not self._scope.is_allowed(ip):
                continue

            self._state.visited.add(ip)
            self._state.hop_count[ip] = hop

            result = self._attempt_move(target, credentials)
            self._state.results.append(result)

            if result.success:
                self._state.compromised.add(ip)
            else:
                self._state.failed.add(ip)

    def _run_dfs(
        self,
        targets: list[dict[str, Any]],
        credentials: dict[str, str],
        hop: int,
    ) -> None:
        """Depth-first propagation."""
        for target in targets[:self._config.max_targets]:
            KillSwitch.check()
            ip = target.get("ip", "")

            if ip in self._state.visited:
                continue
            if hop > self._config.max_hops:
                continue
            if not self._scope.is_allowed(ip):
                continue

            self._state.visited.add(ip)
            self._state.hop_count[ip] = hop

            result = self._attempt_move(target, credentials)
            self._state.results.append(result)

            if result.success:
                self._state.compromised.add(ip)
                # In a real scenario, we'd discover new targets from this host
                # For now, continue to next target
            else:
                self._state.failed.add(ip)

    def _attempt_move(
        self,
        target: dict[str, Any],
        credentials: dict[str, str],
    ) -> MoveResult:
        """Attempt lateral movement to a target using the best protocol."""
        ip = target["ip"]
        protocols = target.get("lateral_protocols", ["SMB"])

        # Pick protocol: use LLM recommendation or first available
        protocol = protocols[0] if protocols else "SMB"

        # Ask LLM for a custom script if available
        custom_script = None
        if self._llm and self._lateral_chain:
            try:
                self._collector.add(Event(
                    event_type=EventType.INFO,
                    target=ip,
                    message=f"Consulting LLM for {protocol} script generation...",
                ))
                
                os_hint = target.get("os_hint", "Unknown")
                script = self._lateral_chain.run(
                    protocol=protocol,
                    target_ip=ip,
                    target_os=os_hint,
                    cred_type="hashes" if credentials.get("hashes") else "password",
                    marker_path="C:\\ransomemu_marker.txt",
                )
                custom_script = script.script_content
                
                self._collector.add(Event(
                    event_type=EventType.INFO,
                    target=ip,
                    message=f"LLM generated custom {script.script_type} script for {protocol} ({len(custom_script)} bytes). Reasoning: {script.explanation}",
                ))
            except Exception as exc:
                logger.warning(f"LLM script generation failed for {ip}: {exc}")

        mover = self._movers.get(protocol)
        if not mover:
            return MoveResult(
                target=ip, protocol=protocol, success=False,
                error=f"No mover for protocol {protocol}",
            )

        self._collector.add(Event(
            event_type=EventType.LATERAL_MOVE,
            target=ip,
            message=f"Attempting {protocol} lateral move to {ip}",
        ))

        # Pass custom_script to mover if supported (WinRM currently supports executing custom PS scripts)
        kwargs = dict(credentials)
        if custom_script and protocol == "WinRM":
            kwargs["custom_script"] = custom_script

        result = mover.execute(target=ip, **kwargs)

        self._collector.add(Event(
            event_type=EventType.LATERAL_MOVE,
            target=ip,
            message=f"{protocol} → {ip}: {'SUCCESS' if result.success else 'FAILED'}",
            data=result.to_dict(),
        ))

        return result
