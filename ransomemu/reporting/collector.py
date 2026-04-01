"""Event collector — thread-safe real-time event tracking."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EventType(str, Enum):
    RECON = "RECON"
    LATERAL_MOVE = "LATERAL_MOVE"
    CRYPTO_MARK = "CRYPTO_MARK"
    PROPAGATION = "PROPAGATION"
    ERROR = "ERROR"
    INFO = "INFO"


@dataclass
class Event:
    """A single simulation event."""

    event_type: EventType
    message: str
    target: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.event_type.value,
            "timestamp": self.timestamp,
            "target": self.target,
            "message": self.message,
            "data": self.data,
        }


class EventCollector:
    """Thread-safe singleton for collecting simulation events."""

    _instance: EventCollector | None = None
    _lock = threading.Lock()

    _events: list[Event]
    _event_lock: threading.Lock

    def __new__(cls) -> EventCollector:
        with cls._lock:
            if cls._instance is None:
                instance: EventCollector = super().__new__(cls)  # type: ignore[misc]
                instance._events = []
                instance._event_lock = threading.Lock()
                cls._instance = instance
            return cls._instance

    def add(self, event: Event) -> None:
        """Add an event to the collection."""
        with self._event_lock:
            self._events.append(event)

    def get_all(self) -> list[Event]:
        """Get all collected events."""
        with self._event_lock:
            return list(self._events)

    def get_by_type(self, event_type: EventType) -> list[Event]:
        """Get events filtered by type."""
        with self._event_lock:
            return [e for e in self._events if e.event_type == event_type]

    def clear(self) -> None:
        """Clear all events."""
        with self._event_lock:
            self._events.clear()

    def to_list(self) -> list[dict]:
        """Export all events as list of dicts."""
        with self._event_lock:
            return [e.to_dict() for e in self._events]

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton (for testing)."""
        cls._instance = None
