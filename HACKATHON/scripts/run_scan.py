#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from urllib import request

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
SAMPLE_DIR = DATA_DIR / "sample"


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


def read_sample(target_id: str, scan_name: str) -> dict:
    sample_path = SAMPLE_DIR / f"{target_id}_{scan_name}.json"
    if sample_path.exists():
        with sample_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    return {"results": [], "target_id": target_id, "scan": scan_name}


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def resolve_source_dir(source_dir: str | Path) -> Path:
    path = Path(source_dir)
    if path.is_absolute() and str(path).startswith("/targets"):
        repo_relative = path.relative_to("/targets")
        return (ROOT / "targets" / repo_relative).resolve()
    if not path.is_absolute():
        return (ROOT / path).resolve()
    return path.resolve()


def run_semgrep(profile: dict) -> dict:
    target_id = profile["target_id"]
    source_dir = resolve_source_dir(profile["source_dir"])
    semgrep_bin = shutil.which("semgrep")
    out_path = RAW_DIR / f"{target_id}-semgrep.json"

    if not source_dir.exists():
        payload = read_sample(target_id, "semgrep")
        write_json(out_path, payload)
        print(f"Source directory missing; wrote sample data for {target_id} from {SAMPLE_DIR / f'{target_id}_semgrep.json'}.")
        return payload

    if semgrep_bin:
        cmd = [semgrep_bin, "--json"]
        for cfg in profile.get("semgrep_configs", []):
            cmd.extend(["--config", cfg])
        cmd.append(str(source_dir))
        proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
        if proc.returncode == 0:
            payload = json.loads(proc.stdout or "{}")
            write_json(out_path, payload)
            return payload

    payload = read_sample(target_id, "semgrep")
    write_json(out_path, payload)
    print(f"Semgrep not available; wrote sample data from {SAMPLE_DIR / f'{target_id}_semgrep.json'}.")
    return payload


def run_dast(profile: dict) -> dict:
    target_id = profile["target_id"]
    target_url = profile["target_url"]
    out_path = RAW_DIR / f"{target_id}-zap.json"

    try:
        with request.urlopen(target_url, timeout=5) as response:
            status = response.status
    except Exception:
        status = None

    payload = {
        "target_id": target_id,
        "scan": "dast",
        "url": target_url,
        "status_code": status,
        "alerts": [
            {
                "url": target_url,
                "method": "GET",
                "param": "placeholder",
                "payload": "demo-payload",
                "evidence": "Profile-based sample scan is active; replace with real ZAP JSON for live execution.",
            }
        ] if status is not None else [],
    }
    write_json(out_path, payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a target-specific SAST/DAST scan profile.")
    parser.add_argument("config", help="Path to a YAML profile file, e.g. configs/flask_demo.yaml")
    parser.add_argument("--dast", action="store_true", help="Also emit the DAST profile output for the selected target")
    args = parser.parse_args()

    profile = load_profile(args.config)
    print(f"Running profile: {profile.get('target_id')} ({profile.get('target_url')})")

    target_id = profile.get("target_id")
    sas = run_semgrep(profile)
    print(f"SAST output: {RAW_DIR / f'{target_id}-semgrep.json'} ({len(sas.get('results', []))} results)")

    if args.dast:
        zap = run_dast(profile)
        print(f"DAST output: {RAW_DIR / f'{target_id}-zap.json'} ({len(zap.get('alerts', []))} alerts)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
