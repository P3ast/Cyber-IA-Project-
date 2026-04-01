"""Network scanner — port scanning and OS detection via SMB banners."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from ransomemu.core.logger import get_logger

logger = get_logger(__name__)

# Ports of interest for lateral movement
LATERAL_PORTS = {
    445: "SMB",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    135: "WMI/RPC",
    139: "NetBIOS",
    22: "SSH",
    3389: "RDP",
}


@dataclass
class HostInfo:
    """Scan result for a single host."""

    ip: str
    hostname: str = ""
    open_ports: dict[int, str] = field(default_factory=dict)
    os_hint: str = ""
    lateral_protocols: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "open_ports": self.open_ports,
            "os_hint": self.os_hint,
            "lateral_protocols": self.lateral_protocols,
        }


def _check_port(ip: str, port: int, timeout: float = 1.5) -> tuple[int, bool]:
    """Check if a single port is open on the target."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port, True
    except (OSError, socket.timeout):
        return port, False


def _grab_smb_banner(ip: str, timeout: float = 2.0) -> str:
    """Attempt to grab the SMB banner for OS hint."""
    try:
        with socket.create_connection((ip, 445), timeout=timeout) as sock:
            # Send SMB negotiate request (minimal)
            sock.sendall(
                b"\x00\x00\x00\x45"  # NetBIOS session
                b"\xff\x53\x4d\x42"  # SMB magic
                b"\x72"              # Negotiate
                + b"\x00" * 64
            )
            data = sock.recv(1024)
            if b"Windows" in data:
                return "Windows"
            if b"Samba" in data:
                return "Linux/Samba"
    except (OSError, socket.timeout):
        pass
    return "Unknown"


def scan_host(ip: str, timeout: float = 1.5) -> HostInfo:
    """Scan a single host for lateral movement ports."""
    info = HostInfo(ip=ip)

    # Reverse DNS
    try:
        info.hostname = socket.getfqdn(ip)
    except OSError:
        pass

    # Port scan
    with ThreadPoolExecutor(max_workers=len(LATERAL_PORTS)) as pool:
        futures = {pool.submit(_check_port, ip, p, timeout): p for p in LATERAL_PORTS}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                proto = LATERAL_PORTS[port]
                info.open_ports[port] = proto

    # Determine available lateral protocols
    if 445 in info.open_ports:
        info.lateral_protocols.append("SMB")
    if 5985 in info.open_ports or 5986 in info.open_ports:
        info.lateral_protocols.append("WinRM")
    if 135 in info.open_ports:
        info.lateral_protocols.append("WMI")
    if 22 in info.open_ports:
        info.lateral_protocols.append("SSH")

    # OS hint from SMB
    if 445 in info.open_ports:
        info.os_hint = _grab_smb_banner(ip)

    return info


def scan_subnet(
    targets: list[str],
    timeout: float = 1.5,
    max_workers: int = 20,
) -> list[HostInfo]:
    """Scan multiple targets in parallel."""
    logger.info(f"🔍 Scanning {len(targets)} targets…")
    results: list[HostInfo] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(scan_host, ip, timeout): ip for ip in targets}
        for future in as_completed(futures):
            info = future.result()
            if info.open_ports:
                logger.info(
                    f"  ✓ {info.ip} — ports: {list(info.open_ports.values())} "
                    f"— protocols: {info.lateral_protocols}"
                )
                results.append(info)

    logger.info(f"📋 {len(results)}/{len(targets)} hosts with open lateral ports")
    return results
