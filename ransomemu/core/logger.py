"""Structured logging with Rich console + JSON file output."""

from __future__ import annotations

import logging
import sys

from rich.console import Console
from rich.logging import RichHandler

_console = Console(stderr=True)
_configured = False


def setup_logging(verbose: bool = False) -> None:
    """Configure root logger with Rich console handler."""
    global _configured
    if _configured:
        return

    level = logging.DEBUG if verbose else logging.INFO

    rich_handler = RichHandler(
        console=_console,
        show_time=True,
        show_path=verbose,
        markup=True,
        rich_tracebacks=True,
    )
    rich_handler.setLevel(level)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[rich_handler],
    )

    # Quiet noisy libraries
    for lib in ("httpx", "httpcore", "urllib3", "impacket"):
        logging.getLogger(lib).setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Get a named logger. Call setup_logging() first for Rich output."""
    return logging.getLogger(name)
