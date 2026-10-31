from __future__ import annotations

import json

from engine.scan_manager.coordinator import apply_task_update, build_scan_state, persist_scan_state


def test_build_scan_state_tracks_totals_and_budget():
    plan = {
        "scan_id": "scan-123",
        "target_id": "flask_demo",
        "target_url": "http://target-flask:5050",
        "deadline_at": "2026-10-31T12:30:00+00:00",
        "targeted_tasks": [{"task_id": "t1", "phase": "TARGETED", "status": "QUEUED"}],
        "broad_tasks": [{"task_id": "b1", "phase": "BROAD", "status": "QUEUED"}],
    }

    state = build_scan_state(plan)

    assert state.scan_id == "scan-123"
    assert state.target_id == "flask_demo"
    assert state.targeted_total == 1
    assert state.broad_total == 1
    assert state.budget_minutes >= 1


def test_apply_task_update_and_persist_state(tmp_path):
    state = build_scan_state(
        {
            "scan_id": "scan-456",
            "target_id": "flask_demo",
            "target_url": "http://target-flask:5050",
            "deadline_at": "2030-01-01T00:00:00+00:00",
            "targeted_tasks": [{"task_id": "t1", "phase": "TARGETED", "status": "QUEUED"}],
            "broad_tasks": [],
        }
    )

    apply_task_update(state, {"task_id": "t1", "phase": "TARGETED", "status": "COMPLETED"})

    assert state.targeted_completed == 1
    assert state.events

    file_path = tmp_path / "scan-state.json"
    persist_scan_state(state, file_path)
    payload = json.loads(file_path.read_text(encoding="utf-8"))

    assert payload["scan_id"] == "scan-456"
    assert payload["targeted_completed"] == 1
    assert payload["events"]
