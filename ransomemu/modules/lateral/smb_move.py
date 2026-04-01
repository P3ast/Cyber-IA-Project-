"""SMB lateral movement via Impacket."""

from __future__ import annotations

from ransomemu.core.logger import get_logger
from ransomemu.modules.lateral.base import LateralMoveBase, MoveResult

logger = get_logger(__name__)

MARKER_CONTENT = "[RANSOMEMU] Simulation marker — {timestamp} — This file proves access.\n"
MARKER_FILENAME = "ransomemu_marker.txt"


class SMBMove(LateralMoveBase):
    """Lateral movement via SMB using Impacket smbclient."""

    protocol = "SMB"

    def _execute(
        self,
        target: str,
        username: str = "",
        password: str = "",
        domain: str = "",
        hashes: str = "",
        share: str = "C$",
        **kwargs,
    ) -> MoveResult:
        from datetime import datetime, timezone

        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            return MoveResult(
                target=target,
                protocol=self.protocol,
                success=False,
                error="impacket not installed",
            )

        lm_hash = ""
        nt_hash = ""
        if hashes and ":" in hashes:
            lm_hash, nt_hash = hashes.split(":", 1)

        try:
            # Connect
            conn = SMBConnection(target, target, sess_port=445, timeout=self._config.timeout)

            # Authenticate
            if hashes:
                conn.login(username, "", domain, lm_hash, nt_hash)
            else:
                conn.login(username, password, domain)

            # Deploy marker file
            marker = MARKER_CONTENT.format(
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            marker_bytes = marker.encode("utf-8")

            from io import BytesIO

            conn.putFile(share, f"\\{MARKER_FILENAME}", BytesIO(marker_bytes).read)

            # Collect system info
            info_output = ""
            try:
                # List shares as proof of access
                shares = conn.listShares()
                share_names = [s["shi1_netname"].rstrip("\0") for s in shares]
                info_output = f"Shares: {share_names}"
            except Exception:
                info_output = "Connected (share listing failed)"

            conn.close()

            return MoveResult(
                target=target,
                protocol=self.protocol,
                success=True,
                output=info_output,
                files_marked=1,
            )

        except Exception as exc:
            return MoveResult(
                target=target,
                protocol=self.protocol,
                success=False,
                error=str(exc),
            )
