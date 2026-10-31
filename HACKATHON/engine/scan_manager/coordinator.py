from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .state import ScanState


def _parse_deadline(deadline_value: str | None) -> int:
    if deadline_value is None:
        return 5
    try:
        deadline = datetime.fromisoformat(deadline_value)
    except ValueError:
        return 5
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    return max(1, int((deadline - datetime.now(timezone.utc)).total_seconds() // 60))


def build_scan_state(plan: dict[str, Any], *, budget_minutes: int | None = None) -> ScanState:
    if not isinstance(plan, dict):
        raise ValueError("Scan plan must be a dictionary")
    target_id = str(plan.get("target_id", "unknown"))
    target_url = str(plan.get("target_url", ""))
    scan_id = str(plan.get("scan_id", "scan-plan"))
    state = ScanState(
        scan_id=scan_id,
        target_id=target_id,
        target_url=target_url,
        budget_minutes=(
            int(budget_minutes)
            if budget_minutes is not None
            else _parse_deadline(plan.get("deadline_at"))
        ),
    )
    state.targeted_total = len(plan.get("targeted_tasks", []))
    state.broad_total = len(plan.get("broad_tasks", []))
    state.started_at = plan.get("created_at") or datetime.now(timezone.utc).isoformat()
    return state


def apply_task_update(state: ScanState, task: dict[str, Any]) -> None:
    if not isinstance(task, dict):
        raise ValueError("Scan task must be a dictionary")
    phase = str(task.get("phase", "UNKNOWN")).upper()
    new_status = str(task.get("status", state.status)).upper()
    if phase == "TARGETED" and new_status == "COMPLETED":
        state.targeted_completed += 1
    if phase == "BROAD" and new_status == "COMPLETED":
        state.broad_completed += 1
    state.record_event(
        "TASK_UPDATE",
        phase,
        f"Task {task.get('task_id', 'unknown')} marked {new_status}",
        task_id=str(task.get("task_id", "unknown")),
        status=new_status,
        route_id=task.get("route_id"),
    )


def persist_scan_state(state: ScanState, path: str | Path) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(state.snapshot(), handle, indent=2)
        handle.write("\n")
