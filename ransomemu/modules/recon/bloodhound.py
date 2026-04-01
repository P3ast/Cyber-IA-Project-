"""BloodHound CE API client — query attack paths and AD relationships."""

from __future__ import annotations

from typing import Any

import httpx

from ransomemu.core.logger import get_logger

logger = get_logger(__name__)


class BloodHoundClient:
    """REST client for BloodHound Community Edition API."""

    def __init__(self, url: str, api_key: str = "", timeout: int = 30) -> None:
        self._base_url = url.rstrip("/")
        self._timeout = timeout
        self._headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

    # ------------------------------------------------------------------
    # Low-level
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict | None = None) -> Any:
        url = f"{self._base_url}{path}"
        try:
            resp = httpx.get(url, headers=self._headers, params=params, timeout=self._timeout)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            logger.error(f"BloodHound API error: {exc}")
            return {}

    def _post(self, path: str, body: dict | None = None) -> Any:
        url = f"{self._base_url}{path}"
        try:
            resp = httpx.post(url, headers=self._headers, json=body or {}, timeout=self._timeout)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            logger.error(f"BloodHound API error: {exc}")
            return {}

    # ------------------------------------------------------------------
    # High-level queries
    # ------------------------------------------------------------------

    def get_domains(self) -> list[dict]:
        """List all AD domains known to BloodHound."""
        data = self._get("/api/v2/available-domains")
        return data.get("data", [])

    def get_shortest_path(self, source: str, target: str) -> dict:
        """Get shortest attack path between two principals."""
        return self._post(
            "/api/v2/graphs/shortest-path",
            {"start_node": source, "end_node": target},
        )

    def get_domain_admins(self, domain_id: str = "") -> list[dict]:
        """Get all users with admin rights on the domain."""
        path = "/api/v2/domains"
        if domain_id:
            path = f"{path}/{domain_id}/admin-users"
        return self._get(path).get("data", [])

    def get_computers(self) -> list[dict]:
        """List all computer objects."""
        return self._get("/api/v2/computers").get("data", [])

    def get_sessions(self) -> list[dict]:
        """List active sessions (user → computer)."""
        return self._get("/api/v2/sessions").get("data", [])

    def get_kerberoastable(self) -> list[dict]:
        """Get Kerberoastable user accounts."""
        return self._get("/api/v2/kerberoast").get("data", [])

    def search(self, query: str) -> list[dict]:
        """Free-text search across BloodHound objects."""
        return self._get("/api/v2/search", params={"q": query}).get("data", [])

    def cypher_query(self, query: str) -> dict:
        """Run a raw Cypher query (BloodHound CE v5+)."""
        return self._post("/api/v2/graphs/cypher", {"query": query})

    # ------------------------------------------------------------------
    # Aggregated
    # ------------------------------------------------------------------

    def collect_recon_summary(self) -> dict[str, Any]:
        """Collect a full recon summary for LLM analysis."""
        logger.info("📡 Collecting BloodHound recon data…")
        return {
            "domains": self.get_domains(),
            "computers": self.get_computers(),
            "sessions": self.get_sessions(),
            "kerberoastable": self.get_kerberoastable(),
        }
