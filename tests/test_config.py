"""Tests for core configuration module."""

from pathlib import Path
import tempfile

import pytest

from ransomemu.core.config import RansomEmuConfig


class TestRansomEmuConfig:
    def test_defaults(self):
        cfg = RansomEmuConfig()
        assert cfg.dry_run is True
        assert cfg.max_hops == 3
        assert cfg.max_targets == 10
        assert cfg.ollama.model == "llama3.1"

    def test_from_yaml(self, tmp_path: Path):
        yml = tmp_path / "test.yml"
        yml.write_text("""
general:
  dry_run: false
  max_hops: 5
ollama:
  model: "llama3.1:8b"
scope:
  allowed_subnets:
    - "10.0.0.0/24"
""")
        cfg = RansomEmuConfig.from_yaml(yml)
        assert cfg.dry_run is False
        assert cfg.max_hops == 5
        assert cfg.ollama.model == "llama3.1:8b"
        assert "10.0.0.0/24" in cfg.scope.allowed_subnets

    def test_from_yaml_missing_file(self):
        cfg = RansomEmuConfig.from_yaml("/nonexistent/path.yml")
        assert cfg.dry_run is True  # Falls back to defaults

    def test_scope_csv_parsing(self):
        cfg = RansomEmuConfig()
        cfg.scope.allowed_subnets = ["10.0.0.0/24", "192.168.1.0/24"]
        assert len(cfg.scope.allowed_subnets) == 2
