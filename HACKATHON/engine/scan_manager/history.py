from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..ingestion.schema import UnifiedFinding

_LOCK = threading.Lock()
_MAX_SNAPSHOTS = 20


def _issue_key(finding: UnifiedFinding) -> str:
    if finding.source == "sast":
        identity = [finding.source, finding.cwe_id, finding.file or "", finding.line or 0]
    else:
        identity = [
            finding.source,
            finding.cwe_id,
            finding.rule_id or "",
            urlparse(finding.url or "").path.rstrip("/") or "/",
            (finding.method or "").upper(),
            finding.parameter or "",
            finding.parameter_source or "",
        ]
    return json.dumps(identity, separators=(",", ":"), ensure_ascii=False)


def record_finding_snapshot(
    data_dir: Path, target_id: str, scan: dict[str, Any], findings: list[UnifiedFinding]
) -> None:
    """Persist a small issue-only snapshot for later scan comparisons."""
    path = data_dir / "raw" / f"{target_id}-finding-history.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    rows: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rows[_issue_key(finding)] = {
            "key": _issue_key(finding),
            "cwe": finding.cwe_id,
            "label": finding.label,
            "severity": finding.severity,
            "file": finding.file,
            "line": finding.line,
            "url": finding.url,
            "method": finding.method,
        }
    snapshot = {
        "scan_id": scan.get("scan_id") or scan.get("job_id"),
        "job_id": scan.get("job_id"),
        "scan_type": scan.get("scan_type"),
        "status": scan.get("status"),
        "finished_at": scan.get("finished_at"),
        "findings": list(rows.values()),
    }
    with _LOCK:
        try:
            history = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(history, list):
                history = []
        except (OSError, json.JSONDecodeError):
            history = []
        history.append(snapshot)
        temporary_path = path.with_name(f".{path.name}.tmp")
        try:
            temporary_path.write_text(
                json.dumps(history[-_MAX_SNAPSHOTS:], indent=2), encoding="utf-8"
            )
            os.replace(temporary_path, path)
        finally:
            temporary_path.unlink(missing_ok=True)


def compare_finding_snapshots(data_dir: Path, target_id: str) -> dict[str, Any]:
    path = data_dir / "raw" / f"{target_id}-finding-history.json"
    try:
        history = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        history = []
    if not isinstance(history, list) or len(history) < 2:
        return {"target_id": target_id, "available": False, "reason": "Complete at least two scans to compare findings."}

    current = history[-1]
    previous = next(
        (snapshot for snapshot in reversed(history[:-1]) if snapshot.get("scan_type") == current.get("scan_type")),
        None,
    )
    if previous is None:
        return {
            "target_id": target_id,
            "available": False,
            "reason": "Run this scan type at least twice to compare results.",
        }
    before = {item["key"]: item for item in previous.get("findings", []) if isinstance(item, dict) and isinstance(item.get("key"), str)}
    after = {item["key"]: item for item in current.get("findings", []) if isinstance(item, dict) and isinstance(item.get("key"), str)}
    return {
        "target_id": target_id,
        "available": True,
        "previous": {"scan_id": previous.get("scan_id"), "scan_type": previous.get("scan_type"), "finished_at": previous.get("finished_at")},
        "current": {"scan_id": current.get("scan_id"), "scan_type": current.get("scan_type"), "finished_at": current.get("finished_at")},
        "new": [after[key] for key in sorted(after.keys() - before.keys())],
        "fixed": [before[key] for key in sorted(before.keys() - after.keys())],
        "still_open": [after[key] for key in sorted(after.keys() & before.keys())],
    }
