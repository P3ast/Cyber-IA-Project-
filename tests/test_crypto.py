"""Tests for the simulation crypto module."""

from pathlib import Path
import pytest

from ransomemu.modules.crypto.simulator import (
    CryptoSimulator,
    MARKER_HEADER,
)


class TestCryptoSimulator:
    @pytest.fixture
    def test_dir(self, tmp_path: Path) -> Path:
        """Create a directory with some target files."""
        d = tmp_path / "test_target"
        d.mkdir()
        
        # Files that should be marked
        (d / "doc.txt").write_text("hello world")
        (d / "data.csv").write_text("1,2,3")
        
        # File that should be skipped
        (d / "script.py").write_text("print('test')")
        
        return d

    def test_mark_file_dry_run(self, test_dir: Path):
        sim = CryptoSimulator(dry_run=True)
        target = test_dir / "doc.txt"
        
        result = sim.mark_file(target)
        assert result.marked is True
        
        # Content should not be changed in dry run
        content = target.read_text()
        assert content == "hello world"

    def test_mark_file_real(self, test_dir: Path):
        sim = CryptoSimulator(dry_run=False)
        target = test_dir / "doc.txt"
        
        result = sim.mark_file(target)
        assert result.marked is True
        assert result.original_size == 11
        
        content = target.read_text()
        assert content.startswith(MARKER_HEADER)
        assert "hello world" in content

    def test_mark_file_already_marked(self, test_dir: Path):
        sim = CryptoSimulator(dry_run=False)
        target = test_dir / "doc.txt"
        
        sim.mark_file(target)
        result2 = sim.mark_file(target)
        
        assert result2.marked is False
        assert result2.error == "already marked"

    def test_mark_directory(self, test_dir: Path):
        sim = CryptoSimulator(dry_run=False)
        stats = sim.mark_directory(test_dir)
        
        assert stats.files_scanned == 3
        assert stats.files_marked == 2
        assert stats.files_skipped == 1
        
        assert ".txt" in stats.by_extension
        assert ".csv" in stats.by_extension

    def test_rollback(self, test_dir: Path):
        sim = CryptoSimulator(dry_run=False)
        target = test_dir / "doc.txt"
        
        # Mark it
        sim.mark_file(target)
        assert target.read_text().startswith(MARKER_HEADER)
        
        # Rollback
        success = CryptoSimulator.rollback_file(target)
        assert success is True
        assert target.read_text() == "hello world"

    def test_rollback_directory(self, test_dir: Path):
        sim = CryptoSimulator(dry_run=False)
        sim.mark_directory(test_dir)
        
        count = CryptoSimulator.rollback_directory(test_dir)
        assert count == 2
        
        assert (test_dir / "doc.txt").read_text() == "hello world"
