from __future__ import annotations

from collections import defaultdict
from typing import Any

from .state import ScanEvent


class EventStore:
    def __init__(self) -> None:
        self._events: dict[str, list[ScanEvent]] = defaultdict(list)

    def append(self, event: ScanEvent) -> ScanEvent:
        self._events[event.scan_id].append(event)
        return event

    def list_events(self, scan_id: str) -> list[ScanEvent]:
        return list(self._events.get(scan_id, []))

    def to_dict(self, scan_id: str | None = None) -> dict[str, Any]:
        if scan_id is None:
            return {
                "events": {
                    event_id: [entry.to_dict() for entry in events]
                    for event_id, events in self._events.items()
                }
            }
        return {"events": [event.to_dict() for event in self._events.get(scan_id, [])]}
