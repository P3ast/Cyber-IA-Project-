"""Crypto simulator — marks files without actual encryption."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ransomemu.core.logger import get_logger

logger = get_logger(__name__)

MARKER_HEADER = "===== RANSOMEMU SIMULATION MARKER ====="
MARKER_TEMPLATE = """{header}
Timestamp: {timestamp}
Host: {hostname}
Simulation ID: {sim_id}
Original size: {original_size} bytes
THIS FILE WAS NOT ENCRYPTED — marker only.
{header}
"""

# File extensions that a real ransomware would target
TARGET_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".txt", ".csv", ".jpg", ".png",
    ".sql", ".mdb", ".bak", ".zip",
}


@dataclass
class MarkResult:
    """Result of a marking operation."""

    path: str
    marked: bool
    original_size: int = 0
    error: str = ""


@dataclass
class SimulationStats:
    """Statistics for the crypto simulation."""

    files_scanned: int = 0
    files_marked: int = 0
    files_skipped: int = 0
    total_size_bytes: int = 0
    by_extension: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "files_marked": self.files_marked,
            "files_skipped": self.files_skipped,
            "total_size_bytes": self.total_size_bytes,
            "by_extension": self.by_extension,
            "errors": self.errors,
        }


class CryptoSimulator:
    """Simulates ransomware file encryption by adding a marker header.

    NO REAL ENCRYPTION is performed. Files are only marked with a
    reversible header to demonstrate access and measure impact scope.
    """

    def __init__(
        self,
        sim_id: str = "default",
        hostname: str = "",
        extensions: set[str] | None = None,
        dry_run: bool = True,
    ) -> None:
        self._sim_id = sim_id
        self._hostname = hostname or os.environ.get("COMPUTERNAME", "unknown")
        self._extensions = extensions or TARGET_EXTENSIONS
        self._dry_run = dry_run
        self._stats = SimulationStats()

    @property
    def stats(self) -> SimulationStats:
        return self._stats

    def mark_file(self, filepath: Path) -> MarkResult:
        """Add a marker header to a single file."""
        try:
            filepath = Path(filepath)
            if not filepath.exists():
                return MarkResult(str(filepath), marked=False, error="file not found")

            original_size = filepath.stat().st_size

            # Check if already marked
            with open(filepath, "r", errors="ignore") as f:
                header = f.read(len(MARKER_HEADER))
                if header == MARKER_HEADER:
                    return MarkResult(str(filepath), marked=False, error="already marked")

            if self._dry_run:
                logger.debug(f"[DRY-RUN] Would mark: {filepath}")
                return MarkResult(str(filepath), marked=True, original_size=original_size)

            # Prepend marker to file
            marker = MARKER_TEMPLATE.format(
                header=MARKER_HEADER,
                timestamp=datetime.now(timezone.utc).isoformat(),
                hostname=self._hostname,
                sim_id=self._sim_id,
                original_size=original_size,
            )

            original_content = filepath.read_bytes()
            with open(filepath, "wb") as f:
                f.write(marker.encode("utf-8"))
                f.write(b"\n")
                f.write(original_content)

            return MarkResult(str(filepath), marked=True, original_size=original_size)

        except Exception as exc:
            return MarkResult(str(filepath), marked=False, error=str(exc))

    def mark_directory(self, directory: Path, recursive: bool = True) -> SimulationStats:
        """Mark all target files in a directory."""
        directory = Path(directory)
        logger.info(f"📁 Scanning {directory} for target files…")

        iterator = directory.rglob("*") if recursive else directory.glob("*")

        for filepath in iterator:
            if not filepath.is_file():
                continue

            self._stats.files_scanned += 1

            if filepath.suffix.lower() not in self._extensions:
                self._stats.files_skipped += 1
                continue

            result = self.mark_file(filepath)

            if result.marked:
                self._stats.files_marked += 1
                self._stats.total_size_bytes += result.original_size
                ext = filepath.suffix.lower()
                self._stats.by_extension[ext] = self._stats.by_extension.get(ext, 0) + 1
            elif result.error:
                self._stats.errors.append(f"{filepath}: {result.error}")

        logger.info(
            f"📊 Scan complete: {self._stats.files_marked}/{self._stats.files_scanned} "
            f"files marked ({self._stats.total_size_bytes} bytes)"
        )
        return self._stats

    @staticmethod
    def rollback_file(filepath: Path) -> bool:
        """Remove the marker header from a file, restoring original content."""
        try:
            content = filepath.read_text(errors="ignore")
            # Find the end of the marker block
            end_marker = MARKER_HEADER + "\n"
            second_marker = content.find(end_marker, len(MARKER_HEADER))
            if second_marker == -1:
                return False

            original = content[second_marker + len(end_marker):]
            filepath.write_text(original)
            logger.info(f"🔄 Rolled back: {filepath}")
            return True
        except Exception as exc:
            logger.error(f"Rollback failed for {filepath}: {exc}")
            return False

    @staticmethod
    def rollback_directory(directory: Path, recursive: bool = True) -> int:
        """Remove markers from all files in a directory."""
        count = 0
        iterator = directory.rglob("*") if recursive else directory.glob("*")
        for filepath in iterator:
            if filepath.is_file():
                try:
                    header = filepath.read_text(errors="ignore")[:len(MARKER_HEADER)]
                    if header == MARKER_HEADER:
                        if CryptoSimulator.rollback_file(filepath):
                            count += 1
                except Exception:
                    pass
        logger.info(f"🔄 Rolled back {count} files in {directory}")
        return count
