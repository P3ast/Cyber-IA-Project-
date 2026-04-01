"""AD enumeration via Impacket — LDAP queries for users, groups, computers."""

from __future__ import annotations

from typing import Any

from ransomemu.core.logger import get_logger

logger = get_logger(__name__)


def enumerate_domain(
    dc_ip: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
) -> dict[str, Any]:
    """Enumerate AD objects via LDAP using Impacket.

    Args:
        dc_ip: Domain Controller IP address.
        domain: AD domain name (e.g. 'corp.local').
        username: Username for LDAP bind.
        password: Plaintext password (or empty if using hashes).
        hashes: NTLM hash in LM:NT format.

    Returns:
        Dictionary of enumerated AD objects.
    """
    try:
        from impacket.ldap import ldap as impacket_ldap
        from impacket.ldap import ldapasn1 as ldapasn1
    except ImportError:
        logger.error("Impacket not installed — skipping AD enumeration")
        return {"error": "impacket not available"}

    result: dict[str, Any] = {
        "users": [],
        "computers": [],
        "groups": [],
        "domain_info": {},
    }

    try:
        base_dn = ",".join(f"DC={part}" for part in domain.split("."))
        logger.info(f"📂 Enumerating AD via LDAP on {dc_ip} (base: {base_dn})")

        ldap_conn = impacket_ldap.LDAPConnection(
            url=f"ldap://{dc_ip}",
            baseDN=base_dn,
        )

        if hashes:
            lm_hash, nt_hash = hashes.split(":")
            ldap_conn.login(username, "", domain, lm_hash, nt_hash)
        else:
            ldap_conn.login(username, password, domain)

        # --- Users ---
        search_filter = "(objectClass=user)"
        attrs = ["sAMAccountName", "displayName", "memberOf", "adminCount", "servicePrincipalName"]
        resp = ldap_conn.search(
            searchFilter=search_filter,
            attributes=attrs,
            sizeLimit=1000,
        )
        for entry in resp:
            if not isinstance(entry, ldapasn1.SearchResultEntry):
                continue
            user = _parse_entry(entry, attrs)
            if user.get("sAMAccountName"):
                result["users"].append(user)

        # --- Computers ---
        search_filter = "(objectClass=computer)"
        attrs = ["dNSHostName", "operatingSystem", "operatingSystemVersion"]
        resp = ldap_conn.search(
            searchFilter=search_filter,
            attributes=attrs,
            sizeLimit=1000,
        )
        for entry in resp:
            if not isinstance(entry, ldapasn1.SearchResultEntry):
                continue
            computer = _parse_entry(entry, attrs)
            if computer.get("dNSHostName"):
                result["computers"].append(computer)

        # --- Groups ---
        search_filter = "(&(objectClass=group)(adminCount=1))"
        attrs = ["sAMAccountName", "member"]
        resp = ldap_conn.search(
            searchFilter=search_filter,
            attributes=attrs,
            sizeLimit=500,
        )
        for entry in resp:
            if not isinstance(entry, ldapasn1.SearchResultEntry):
                continue
            group = _parse_entry(entry, attrs)
            if group.get("sAMAccountName"):
                result["groups"].append(group)

        logger.info(
            f"  ✓ Found {len(result['users'])} users, "
            f"{len(result['computers'])} computers, "
            f"{len(result['groups'])} admin groups"
        )

    except Exception as exc:
        logger.error(f"AD enumeration failed: {exc}")
        result["error"] = str(exc)

    return result


def _parse_entry(entry: Any, attributes: list[str]) -> dict[str, str]:
    """Parse an LDAP SearchResultEntry into a flat dict."""
    parsed: dict[str, str] = {}
    try:
        for attr in entry["attributes"]:
            attr_type = str(attr["type"])
            if attr_type in attributes:
                values = [str(v) for v in attr["vals"]]
                parsed[attr_type] = values[0] if len(values) == 1 else ", ".join(values)
    except Exception:
        pass
    return parsed
