#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parent.parent
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


def run_compose(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["docker", "compose", *command],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Docker Compose is required to run containerized scans") from exc


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
        "semgrep",
        "scan",
        "--json",
        "--output",
        "{report}",
    ]
    for config in profile.get("semgrep_configs", []):
        command.extend(["--config", str(config)])
    for excluded in profile.get("exclude", []):
        command.extend(["--exclude", str(excluded)])
    command.append(container_source)

    report = scan_report(target_id, "semgrep", command, {0, 1}, ("results",))
    if not isinstance(report.get("results", []), list):
        raise ValueError("Semgrep JSON 'results' must be a list")
    return report


def run_dast(profile: dict) -> dict:
    target_id = profile["target_id"]
    service, target_url = validate_target(profile)
    max_minutes = int(profile.get("zap_max_minutes", 5))
    if not 1 <= max_minutes <= 30:
        raise ValueError("zap_max_minutes must be between 1 and 30")

    target_start = run_compose(["up", "--detach", "--wait", service])
    if target_start.returncode != 0:
        details = (target_start.stderr or target_start.stdout).strip()
        raise RuntimeError(
            f"Could not start healthy target {service}: "
            f"{details[-2000:] or 'no diagnostic output'}"
        )

    command = [
        "--profile",
        "scanners",
        "run",
        "--rm",
        "--no-deps",
        "zap",
        "zap-full-scan.py",
        "-t",
        target_url,
        "-J",
        "{report}",
        "-m",
        str(max_minutes),
        "-T",
        str(max_minutes * 2),
        "-I",
    ]
    report = scan_report(target_id, "zap", command, {0, 1, 2}, ("alerts", "site"))
    return report


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
    args = parser.parse_args()

    profile = load_profile(args.config)
    print(f"Running profile: {profile.get('target_id')} ({profile.get('target_url')})")

    target_id = profile.get("target_id")
    sast = run_semgrep(profile)
    print(f"SAST output: {RAW_DIR / f'{target_id}-semgrep.json'} ({len(sast.get('results', []))} results)")

    if args.dast:
        zap = run_dast(profile)
        print(f"DAST output: {RAW_DIR / f'{target_id}-zap.json'} ({count_zap_alerts(zap)} alerts)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
