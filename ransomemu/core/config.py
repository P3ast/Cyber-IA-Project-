"""RansomEmu configuration — Pydantic settings with YAML + env support."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class OllamaSettings(BaseSettings):
    """Ollama LLM connection settings."""

    base_url: str = "http://ollama:11434"
    model: str = "llama3.1"
    temperature: float = 0.1
    timeout: int = 120

    model_config = SettingsConfigDict(env_prefix="OLLAMA_")


class BloodHoundSettings(BaseSettings):
    """BloodHound CE API settings."""

    url: str = "http://localhost:8080"
    api_key: str = ""
    timeout: int = 30

    model_config = SettingsConfigDict(env_prefix="BLOODHOUND_")


class ScopeSettings(BaseSettings):
    """Target scope restrictions."""

    allowed_subnets: list[str] = Field(default_factory=list)
    excluded_hosts: list[str] = Field(default_factory=list)

    model_config = SettingsConfigDict(env_prefix="RANSOMEMU_")

    @field_validator("allowed_subnets", "excluded_hosts", mode="before")
    @classmethod
    def _split_csv(cls, v: str | list) -> list[str]:
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return v


class RansomEmuConfig(BaseSettings):
    """Main configuration for RansomEmu."""

    # General
    dry_run: bool = True
    max_hops: int = 3
    max_targets: int = 10
    timeout: int = 300
    verbose: bool = False

    # Sub-configs
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)
    bloodhound: BloodHoundSettings = Field(default_factory=BloodHoundSettings)
    scope: ScopeSettings = Field(default_factory=ScopeSettings)

    model_config = SettingsConfigDict(env_prefix="RANSOMEMU_")

    @classmethod
    def from_yaml(cls, path: Optional[str | Path] = None) -> "RansomEmuConfig":
        """Load configuration from a YAML file, with env overrides."""
        if path is None:
            path = _PROJECT_ROOT / "config" / "default.yml"
        path = Path(path)

        data: dict = {}
        if path.exists():
            with open(path) as f:
                raw = yaml.safe_load(f) or {}
            # Flatten 'general' key into top-level
            data.update(raw.get("general", {}))
            data["ollama"] = raw.get("ollama", {})
            data["bloodhound"] = raw.get("bloodhound", {})
            data["scope"] = raw.get("scope", {})

        return cls(**data)
