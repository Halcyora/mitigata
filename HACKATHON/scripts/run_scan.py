#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.adapters.base import TargetProfile
from engine.ast_mapper.call_graph import build_call_graph
from engine.dast_planner.planner import ScanPlan, build_scan_plan
from engine.ingestion.semgrep_parser import parse_semgrep_json
from engine.scan_manager.coordinator import apply_task_update, build_scan_state, persist_scan_state

DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
TARGETS_DIR = ROOT / "targets"

TARGET_SERVICES = {
    "flask_demo": ("target-flask", 5050),
    "juice_shop": ("target-juice-shop", 3000),
}


def load_profile(config_path: str | Path) -> dict:
    path = Path(config_path)
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Config not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        profile = yaml.safe_load(handle) or {}
    if not profile:
        raise ValueError(f"Profile file is empty: {path}")
    return profile


def resolve_source_dir(source_dir: str | Path) -> Path:
    raw_path = str(source_dir).replace("\\", "/")
    if raw_path == "/targets" or raw_path.startswith("/targets/"):
        relative = Path(*raw_path.removeprefix("/targets").strip("/").split("/"))
        path = TARGETS_DIR / relative
    else:
        path = Path(source_dir)
        if not path.is_absolute():
            path = ROOT / path
    resolved = path.resolve()
    try:
        resolved.relative_to(TARGETS_DIR.resolve())
    except ValueError as exc:
        raise ValueError(f"Source directory must be inside {TARGETS_DIR}: {source_dir}") from exc
    return resolved


def validate_target(profile: dict) -> tuple[str, str]:
    target_id = profile["target_id"]
    expected = TARGET_SERVICES.get(target_id)
    if expected is None:
        raise ValueError(f"Unsupported DAST target profile: {target_id}")
    expected_service, expected_port = expected
    service = profile.get("docker_service")
    parsed_url = urlsplit(str(profile.get("target_url", "")))

    if (
        service != expected_service
        or parsed_url.scheme != "http"
        or parsed_url.hostname != expected_service
        or parsed_url.port != expected_port
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise ValueError(
            f"DAST target must be the configured internal service "
            f"http://{expected_service}:{expected_port}"
        )
    return expected_service, parsed_url.geturl()


def run_compose(
    command: list[str], *, timeout_seconds: float | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["docker", "compose", *command],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Docker Compose command exceeded the DAST time budget") from exc
    except FileNotFoundError as exc:
        raise RuntimeError("Docker Compose is required to run containerized scans") from exc


def run_docker(
    command: list[str],
    *,
    input_text: str | None = None,
    timeout_seconds: float | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["docker", *command],
            cwd=str(ROOT),
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Docker command exceeded the DAST time budget") from exc
    except FileNotFoundError as exc:
        raise RuntimeError("Docker is required to run containerized scans") from exc


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def scan_report(
    target_id: str,
    scan_name: str,
    command: list[str],
    acceptable_returncodes: set[int],
    required_keys: tuple[str, ...],
) -> dict:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    final_path = RAW_DIR / f"{target_id}-{scan_name}.json"
    temporary_path = RAW_DIR / f".{target_id}-{scan_name}-{uuid.uuid4().hex}.json"
    container_report = f"/output/{temporary_path.name}"
    command = [container_report if part == "{report}" else part for part in command]
    try:
        process = run_compose(command)
        if process.returncode not in acceptable_returncodes:
            details = (process.stderr or process.stdout).strip()
            raise RuntimeError(
                f"{scan_name.upper()} scanner failed (exit {process.returncode}): "
                f"{details[-2000:] or 'no diagnostic output'}"
            )
        if not temporary_path.is_file():
            raise RuntimeError(
                f"{scan_name.upper()} scanner completed without creating its JSON report"
            )
        with temporary_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError(f"{scan_name.upper()} report root must be a JSON object")
        if not any(key in payload for key in required_keys):
            expected = " or ".join(repr(key) for key in required_keys)
            raise ValueError(f"{scan_name.upper()} report must contain {expected}")
        os.replace(temporary_path, final_path)
        return payload
    finally:
        temporary_path.unlink(missing_ok=True)


def run_semgrep(profile: dict) -> dict:
    target_id = profile["target_id"]
    source_dir = resolve_source_dir(profile["source_dir"])
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Target source directory does not exist: {source_dir}")
    container_source = "/targets/" + source_dir.relative_to(TARGETS_DIR.resolve()).as_posix()
    command = [
        "--profile",
        "scanners",
        "run",
        "--rm",
        "--no-deps",
    ]
    ca_path = os.environ.get("MITIGATA_CA_CERT_PATH")
    if ca_path:
        trusted_ca = Path(ca_path).expanduser()
        if not trusted_ca.is_file():
            raise FileNotFoundError(
                f"MITIGATA_CA_CERT_PATH must point to a readable CA certificate: {trusted_ca}"
            )
        command.extend(
            [
                "--volume",
                f"{trusted_ca.resolve().as_posix()}:"
                "/run/secrets/mitigata-ca.crt:ro",
                "--env",
                "REQUESTS_CA_BUNDLE=/run/secrets/mitigata-ca.crt",
            ]
        )
    command.extend(
        [
            "semgrep",
            "scan",
            "--json",
            "--output",
            "{report}",
        ]
    )
    for config in profile.get("semgrep_configs", []):
        command.extend(["--config", str(config)])
    for excluded in profile.get("exclude", []):
        command.extend(["--exclude", str(excluded)])
    command.append(container_source)

    report = scan_report(target_id, "semgrep", command, {0, 1}, ("results",))
    if not isinstance(report.get("results", []), list):
        raise ValueError("Semgrep JSON 'results' must be a list")
    return report


def _build_profile_scan_plan(
    profile: dict,
    budget_minutes: int,
    *,
    deadline_at: str | None = None,
) -> ScanPlan:
    target_id = profile["target_id"]
    _, target_url = validate_target(profile)
    source_dir = resolve_source_dir(profile["source_dir"])
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Target source directory does not exist: {source_dir}")
    language = profile.get("language")
    framework = profile.get("framework")
    if not isinstance(language, str) or not isinstance(framework, str):
        raise ValueError(f"Target profile {target_id!r} lacks adapter metadata")
    graph = build_call_graph(
        TargetProfile(
            target_id=target_id,
            language=language,
            framework=framework,
            source_dir=source_dir,
        )
    )
    routes = graph.get("routes")
    if not isinstance(routes, list):
        raise ValueError("AST route mapper did not return a route inventory")
    semgrep_path = RAW_DIR / f"{target_id}-semgrep.json"
    if not semgrep_path.is_file():
        raise FileNotFoundError(
            f"SAST report is required before targeted DAST: {semgrep_path}"
        )
    findings = parse_semgrep_json(semgrep_path, target_id)
    return build_scan_plan(
        target_id,
        target_url,
        findings,
        routes,
        budget_minutes=budget_minutes,
        model_mode=os.getenv("GRAPHCODEBERT_MODE", "ON"),
        source_revision=str(profile.get("target_revision") or "unknown"),
        source_root=source_dir,
        deadline_at=deadline_at,
    )


def run_zap_plan(plan: ScanPlan) -> dict:
    target_id = plan.target_id
    plan_path = RAW_DIR / f"{target_id}-scan-plan.json"
    report_path = RAW_DIR / f"{target_id}-zap.json"
    state_path = RAW_DIR / f"{target_id}-scan-state.json"
    scan_state = build_scan_state(plan.to_dict())
    scan_state.status = "RUNNING"
    scan_state.started_at = plan.created_at
    scan_state.record_event(
        "PLAN_READY",
        "PLANNED",
        "Scan plan created and persisted",
        task_id=None,
        deadline_at=plan.deadline_at,
    )
    persist_scan_state(scan_state, state_path)
    write_json(plan_path, plan.to_dict())

    container_name = f"mitigata-zap-{uuid.uuid4().hex[:12]}"
    api_key = secrets.token_urlsafe(32)
    remaining_seconds = max(
        0.1,
        (datetime.fromisoformat(plan.deadline_at) - datetime.now(timezone.utc)).total_seconds(),
    )
    try:
        started = run_compose(
            [
                "--profile",
                "scanners",
                "run",
                "--detach",
                "--name",
                container_name,
                "--no-deps",
                "--entrypoint",
                "zap.sh",
                "zap",
                "-daemon",
                "-host",
                "127.0.0.1",
                "-port",
                "8090",
                "-config",
                f"api.key={api_key}",
                "-config",
                "telemetry.enabled=false",
            ],
            timeout_seconds=remaining_seconds,
        )
    except RuntimeError:
        run_docker(["rm", "-f", container_name], timeout_seconds=5)
        raise
    if started.returncode != 0:
        details = (started.stderr or started.stdout).strip()
        raise RuntimeError(
            f"Could not start isolated ZAP daemon: "
            f"{details[-2000:] or 'no diagnostic output'}"
        )

    driver_input = json.dumps({"api_key": api_key, "plan": plan.to_dict()})
    try:
        driver_timeout = max(
            0.1,
            (datetime.fromisoformat(plan.deadline_at) - datetime.now(timezone.utc)).total_seconds(),
        )
        execution = run_docker(
            [
                "exec",
                "-i",
                container_name,
                "python3",
                "/workspace/zap_api_driver.py",
            ],
            input_text=driver_input,
            timeout_seconds=driver_timeout,
        )
        if execution.returncode != 0:
            details = (execution.stderr or execution.stdout).strip()
            raise RuntimeError(
                f"ZAP route orchestration failed: "
                f"{details[-3000:] or 'no diagnostic output'}"
            )
        report = json.loads(execution.stdout)
        if not isinstance(report, dict) or not isinstance(report.get("alerts"), list):
            raise ValueError("ZAP orchestrator returned an invalid scan report")
        if not isinstance(report.get("tasks"), list):
            raise ValueError("ZAP orchestrator report is missing task states")
        task_states = {
            task.get("task_id"): task
            for task in report["tasks"]
            if isinstance(task, dict)
        }
        for task in [*plan.targeted_tasks, *plan.broad_tasks]:
            state = task_states.get(task.task_id)
            if state is not None:
                task.status = str(state.get("status", task.status))
            task_dict = state or {}
            for field in ("started_at", "finished_at", "progress", "error"):
                if field in task_dict:
                    setattr(task, field, task_dict[field])
        plan.status = str(report.get("scan_status", plan.status))
        scan_state.status = plan.status
        scan_state.cutoff = bool(report.get("coverage", {}).get("cutoff", False))
        scan_state.update_status(plan.status)
        for task in report.get("tasks", []):
            apply_task_update(scan_state, task)
        scan_state.record_event(
            "SCAN_FINISHED",
            "FINALIZING",
            "Scan run complete",
            scan_id=plan.scan_id,
            status=plan.status,
            coverage=report.get("coverage", {}),
        )
        persist_scan_state(scan_state, state_path)
        write_json(plan_path, plan.to_dict())
        write_json(report_path, report)
        return report
    finally:
        stopped = run_docker(["rm", "-f", container_name], timeout_seconds=5)
        if stopped.returncode != 0:
            details = (stopped.stderr or stopped.stdout).strip()
            raise RuntimeError(
                f"Could not remove temporary ZAP container {container_name}: "
                f"{details[-1000:] or 'no diagnostic output'}"
            )


def run_dast(profile: dict, *, budget_minutes: int | None = None) -> dict:
    target_id = profile["target_id"]
    service, _ = validate_target(profile)
    selected_budget = budget_minutes
    if selected_budget is None:
        selected_budget = int(profile.get("zap_max_minutes", 5))
    if not 1 <= selected_budget <= 30:
        raise ValueError("DAST time budget must be between 1 and 30 minutes")

    # DAST needs a live target and a completed plan; the five-minute clock is
    # the bounded ZAP execution window and includes ZAP startup and cleanup.
    target_start = run_compose(["up", "--detach", "--wait", service])
    if target_start.returncode != 0:
        details = (target_start.stderr or target_start.stdout).strip()
        raise RuntimeError(
            f"Could not start healthy target {service}: "
            f"{details[-2000:] or 'no diagnostic output'}"
        )

    plan = _build_profile_scan_plan(profile, selected_budget)
    deadline = datetime.now(timezone.utc) + timedelta(minutes=selected_budget)
    plan.deadline_at = deadline.isoformat()
    return run_zap_plan(plan)


def count_zap_alerts(report: dict) -> int:
    alerts = report.get("alerts")
    if alerts is not None and not isinstance(alerts, list):
        raise ValueError("ZAP report 'alerts' must be a list")
    if alerts:
        return len(alerts)

    sites = report.get("site", [])
    if not isinstance(sites, list):
        raise ValueError("ZAP report 'site' must be a list")
    count = 0
    for site in sites:
        if not isinstance(site, dict):
            raise ValueError("Each ZAP site entry must be an object")
        site_alerts = site.get("alerts", [])
        if not isinstance(site_alerts, list):
            raise ValueError("ZAP site 'alerts' must be a list")
        count += len(site_alerts)
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description="Run containerized SAST/DAST scans for a target profile.")
    parser.add_argument("config", help="Path to a YAML profile file, e.g. configs/flask_demo.yaml")
    parser.add_argument("--dast", action="store_true", help="Also run the bounded ZAP active scan")
    parser.add_argument("--dast-minutes", type=int, help="Override the 1-30 minute DAST time budget")
    args = parser.parse_args()

    profile = load_profile(args.config)
    print(f"Running profile: {profile.get('target_id')} ({profile.get('target_url')})")

    target_id = profile.get("target_id")
    sast = run_semgrep(profile)
    print(f"SAST output: {RAW_DIR / f'{target_id}-semgrep.json'} ({len(sast.get('results', []))} results)")

    if args.dast:
        zap = run_dast(profile, budget_minutes=args.dast_minutes)
        coverage = zap.get("coverage", {})
        print(
            f"DAST output: {RAW_DIR / f'{target_id}-zap.json'} "
            f"({count_zap_alerts(zap)} alerts; {zap.get('scan_status')}; "
            f"{coverage.get('targeted_completed', 0)} targeted and "
            f"{coverage.get('broad_completed', 0)} broad tasks completed)"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
