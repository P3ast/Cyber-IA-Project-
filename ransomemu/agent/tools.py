"""LangChain tool definitions for the LLM agent."""

from __future__ import annotations

from typing import Any

from langchain_core.tools import tool

from ransomemu.core.logger import get_logger

logger = get_logger(__name__)

# These tools are registered with the LangChain agent so the LLM can
# autonomously trigger recon and lateral-move operations.


@tool
def scan_network_tool(targets: str) -> str:
    """Scan a comma-separated list of IPs for lateral movement ports.

    Args:
        targets: Comma-separated list of IP addresses to scan.

    Returns:
        JSON string of scan results.
    """
    import json

    from ransomemu.modules.recon.network import scan_subnet

    ip_list = [t.strip() for t in targets.split(",") if t.strip()]
    results = scan_subnet(ip_list)
    return json.dumps([r.to_dict() for r in results], indent=2)


@tool
def query_bloodhound_tool(query_type: str) -> str:
    """Query BloodHound CE for AD intelligence.

    Args:
        query_type: One of 'domains', 'computers', 'sessions', 'kerberoastable', 'summary'.

    Returns:
        JSON string of query results.
    """
    import json

    from ransomemu.modules.recon.bloodhound import BloodHoundClient

    # Client will be configured via env vars at runtime
    client = BloodHoundClient(
        url="http://localhost:8080",  # overridden at runtime
    )

    handlers = {
        "domains": client.get_domains,
        "computers": client.get_computers,
        "sessions": client.get_sessions,
        "kerberoastable": client.get_kerberoastable,
        "summary": client.collect_recon_summary,
    }

    handler = handlers.get(query_type)
    if not handler:
        return f"Unknown query type: {query_type}. Use one of: {list(handlers.keys())}"

    return json.dumps(handler(), indent=2)


@tool
def check_port_tool(target: str, port: int) -> str:
    """Check if a specific port is open on a target.

    Args:
        target: IP address or hostname.
        port: Port number to check.

    Returns:
        'open' or 'closed'.
    """
    from ransomemu.modules.recon.network import _check_port

    _, is_open = _check_port(target, port)
    return "open" if is_open else "closed"


# Registry of all tools for the agent
ALL_TOOLS = [scan_network_tool, query_bloodhound_tool, check_port_tool]
