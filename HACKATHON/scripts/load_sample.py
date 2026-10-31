#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
SAMPLE_DIR = DATA_DIR / "sample"


def load_profile(config_path: str | Path) -> dict:
    path = Path(config_path)
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    with path.open("r", encoding="utf-8") as handle:
        profile = yaml.safe_load(handle) or {}
    return profile


def copy_sample(profile: dict) -> None:
    target_id = profile["target_id"]
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    for scan_name in ("semgrep", "zap"):
        sample_name = f"{target_id}_{scan_name}.json"
        sample_path = SAMPLE_DIR / sample_name
        raw_path = RAW_DIR / f"{target_id}-{scan_name}.json"
        if sample_path.exists():
            shutil.copy2(sample_path, raw_path)
            print(f"Loaded {sample_path} -> {raw_path}")
        else:
            payload = {"target_id": target_id, "scan": scan_name, "results": [], "alerts": []}
            if scan_name == "semgrep":
                payload = {"target_id": target_id, "scan": scan_name, "results": []}
            raw_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            print(f"Created empty sample output at {raw_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Load committed sample scan fixtures for a target profile.")
    parser.add_argument("config", help="Path to a YAML profile file, e.g. configs/flask_demo.yaml")
    args = parser.parse_args()

    profile = load_profile(args.config)
    copy_sample(profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
