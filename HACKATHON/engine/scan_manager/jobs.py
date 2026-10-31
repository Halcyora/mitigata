from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4


_ACTIVE_STATUSES = {"SAST_RUNNING", "DAST_RUNNING"}


class ScanAlreadyRunning(RuntimeError):
    def __init__(self, job: dict[str, Any]) -> None:
        super().__init__("A SAST/DAST scan is already running")
        self.job = job


class ScanJobManager:
    """Run the existing SAST-then-DAST pipeline and expose its real status."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()
        self._lock = threading.RLock()
        self._jobs: dict[str, dict[str, Any]] = {}

    def start(
        self, target_id: str, scan_type: Literal["sast", "dast"]
    ) -> dict[str, Any]:
        with self._lock:
            active = next(
                (
                    job
                    for job in reversed(list(self._jobs.values()))
                    if job["status"] in _ACTIVE_STATUSES
                ),
                None,
            )
            if active is not None:
                raise ScanAlreadyRunning(self._public_snapshot(active))

            job_id = str(uuid4())
            job = {
                "job_id": job_id,
                "target_id": target_id,
                "scan_type": scan_type,
                "status": "SAST_RUNNING" if scan_type == "sast" else "DAST_RUNNING",
                "phase": "SAST" if scan_type == "sast" else "DAST",
                "message": (
                    "Semgrep is running. Start DAST separately when SAST completes."
                    if scan_type == "sast"
                    else "Using the saved Semgrep report to plan and run targeted DAST, then broad fallback."
                ),
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": None,
                "scan_id": None,
                "budget_minutes": None,
                "targeted_total": 0,
                "targeted_completed": 0,
                "broad_total": 0,
                "broad_completed": 0,
                "cutoff": False,
                "error": None,
                "log_path": self.project_root
                / "data"
                / "raw"
                / f"{target_id}-scan-job-{job_id}.log",
            }
            self._jobs[job_id] = job
            worker = threading.Thread(
                target=self._run,
                args=(job_id,),
                name=f"scan-{target_id}-{job_id[:8]}",
                daemon=True,
            )
            worker.start()
            return self._public_snapshot(job)

    def latest(self, target_id: str) -> dict[str, Any] | None:
        with self._lock:
            matches = [
                job for job in self._jobs.values() if job["target_id"] == target_id
            ]
            if not matches:
                return None
            return self._public_snapshot(matches[-1])

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return self._public_snapshot(job) if job is not None else None

    def _public_snapshot(self, job: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in job.items() if key != "log_path"}

    def _read_fresh_state(self, job: dict[str, Any]) -> dict[str, Any] | None:
        state_path = (
            self.project_root
            / "data"
            / "raw"
            / f"{job['target_id']}-scan-state.json"
        )
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            started_at = datetime.fromisoformat(str(state.get("started_at")))
            submitted_at = datetime.fromisoformat(str(job["started_at"]))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return None
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        if submitted_at.tzinfo is None:
            submitted_at = submitted_at.replace(tzinfo=timezone.utc)
        return state if started_at >= submitted_at else None

    def _apply_execution_state(
        self, job_id: str, state: dict[str, Any]
    ) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job.update(
                {
                    "status": "DAST_RUNNING",
                    "phase": "DAST",
                    "message": "Targeted DAST is running; broad route checks follow if budget remains.",
                    "scan_id": state.get("scan_id"),
                    "budget_minutes": state.get("budget_minutes"),
                    "targeted_total": state.get("targeted_total", 0),
                    "targeted_completed": state.get("targeted_completed", 0),
                    "broad_total": state.get("broad_total", 0),
                    "broad_completed": state.get("broad_completed", 0),
                    "cutoff": bool(state.get("cutoff", False)),
                }
            )

    def _run(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
            target_id = str(job["target_id"])
            scan_type = str(job["scan_type"])
            log_path = Path(job["log_path"])

        scan_option = "--sast-only" if scan_type == "sast" else "--dast-only"
        command = [
            sys.executable,
            "-u",
            str(self.project_root / "scripts" / "run_scan.py"),
            str(self.project_root / "configs" / f"{target_id}.yaml"),
            scan_option,
        ]
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("w", encoding="utf-8") as output:
                process = subprocess.Popen(
                    command,
                    cwd=self.project_root,
                    env=os.environ.copy(),
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                while process.poll() is None:
                    state = self._read_fresh_state(job)
                    if state is not None:
                        self._apply_execution_state(job_id, state)
                    time.sleep(0.5)
                return_code = process.wait()
        except OSError as exc:
            self._finish(job_id, "FAILED", f"Could not start scan runner: {exc}")
            return

        state = self._read_fresh_state(job)
        if state is not None:
            with self._lock:
                current = self._jobs[job_id]
                current.update(
                    {
                        "scan_id": state.get("scan_id"),
                        "budget_minutes": state.get("budget_minutes"),
                        "targeted_total": state.get("targeted_total", 0),
                        "targeted_completed": state.get("targeted_completed", 0),
                        "broad_total": state.get("broad_total", 0),
                        "broad_completed": state.get("broad_completed", 0),
                        "cutoff": bool(state.get("cutoff", False)),
                    }
                )

        if return_code != 0:
            try:
                details = log_path.read_text(encoding="utf-8", errors="replace")[-2500:]
            except OSError:
                details = ""
            self._finish(
                job_id,
                "FAILED",
                details.strip() or f"Scan runner exited with code {return_code}.",
            )
            return

        if scan_type == "sast":
            final_status = "SAST_COMPLETED"
            message = "SAST completed and its report is saved. Start DAST when ready."
        else:
            final_status = str(state.get("status", "COMPLETED")) if state else "COMPLETED"
            message = (
                "DAST and all planned tasks completed."
                if final_status == "COMPLETED"
                else "DAST finished with incomplete coverage; inspect skipped or timed-out tasks."
            )
        self._finish(job_id, final_status, message)

    def _finish(self, job_id: str, status: str, message: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job.update(
                {
                    "status": status,
                    "phase": "FINISHED",
                    "message": message,
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                    "error": message if status == "FAILED" else None,
                }
            )


scan_jobs = ScanJobManager(Path(__file__).resolve().parents[2])
