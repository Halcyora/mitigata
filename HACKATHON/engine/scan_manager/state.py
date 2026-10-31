from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanEvent:
    scan_id: str
    kind: str
    phase: str
    message: str = ""
    task_id: str | None = None
    created_at: str = field(default_factory=_utc_now)
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": str(uuid4()),
            "scan_id": self.scan_id,
            "kind": self.kind,
            "phase": self.phase,
            "message": self.message,
            "task_id": self.task_id,
            "created_at": self.created_at,
            "payload": self.payload,
        }


@dataclass
class ScanState:
    scan_id: str
    target_id: str
    target_url: str
    status: str = "PLANNED"
    budget_minutes: int = 5
    started_at: str | None = None
    finished_at: str | None = None
    cutoff: bool = False
    targeted_total: int = 0
    broad_total: int = 0
    targeted_completed: int = 0
    broad_completed: int = 0
    events: list[ScanEvent] = field(default_factory=list)

    def record_event(
        self,
        kind: str,
        phase: str,
        message: str,
        *,
        task_id: str | None = None,
        **payload: Any,
    ) -> ScanEvent:
        event = ScanEvent(
            scan_id=self.scan_id,
            kind=kind,
            phase=phase,
            message=message,
            task_id=task_id,
            payload=dict(payload),
        )
        self.events.append(event)
        return event

    def update_status(self, status: str) -> None:
        self.status = status
        if status in {"COMPLETED", "INCOMPLETE", "FAILED"}:
            self.finished_at = self.finished_at or _utc_now()

    def snapshot(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_id": self.target_id,
            "target_url": self.target_url,
            "status": self.status,
            "budget_minutes": self.budget_minutes,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "cutoff": self.cutoff,
            "targeted_total": self.targeted_total,
            "broad_total": self.broad_total,
            "targeted_completed": self.targeted_completed,
            "broad_completed": self.broad_completed,
            "events": [event.to_dict() for event in self.events],
        }
