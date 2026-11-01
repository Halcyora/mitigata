from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any


_TARGETS = {"flask_demo", "juice_shop"}
_MAX_STORE_BYTES = 2_000_000
_LOCK = threading.RLock()


def _store_path(target_id: str) -> Path:
    if target_id not in _TARGETS:
        raise ValueError("Unknown target")
    return Path(__file__).resolve().parents[1] / "data" / "raw" / f"{target_id}-verification.json"


def load_confirmed_results(target_id: str) -> dict[str, dict[str, Any]]:
    """Load bounded, target-scoped positive runtime verification records."""
    path = _store_path(target_id)
    try:
        if path.stat().st_size > _MAX_STORE_BYTES:
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict) or payload.get("target_id") != target_id:
        return {}
    findings = payload.get("findings")
    if not isinstance(findings, dict):
        return {}
    return {
        finding_id: result
        for finding_id, result in findings.items()
        if isinstance(finding_id, str)
        and isinstance(result, dict)
        and result.get("label") == "Confirmed"
    }


def _write_store(target_id: str, findings: dict[str, dict[str, Any]]) -> None:
    path = _store_path(target_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {"version": 1, "target_id": target_id, "findings": findings},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    if len(payload.encode("utf-8")) > _MAX_STORE_BYTES:
        raise ValueError("Verification result store is full")
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = handle.name
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)


def save_confirmed_result(
    target_id: str, finding_id: str, result: dict[str, Any]
) -> None:
    if not finding_id or result.get("label") != "Confirmed":
        raise ValueError("Only confirmed findings can be persisted")
    with _LOCK:
        findings = load_confirmed_results(target_id)
        findings[finding_id] = result
        _write_store(target_id, findings)


def clear_verification_result(target_id: str, finding_id: str) -> None:
    """Remove stale positive proof before a fresh retest begins."""
    with _LOCK:
        findings = load_confirmed_results(target_id)
        if finding_id not in findings:
            return
        del findings[finding_id]
        _write_store(target_id, findings)


def clear_target_verifications(target_id: str) -> None:
    """Clear proofs when source code is changed or a fresh SAST baseline begins."""
    with _LOCK:
        _write_store(target_id, {})
