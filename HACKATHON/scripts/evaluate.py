"""Compare scanner JSON output with a target-scoped YAML ground-truth manifest."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.ingestion.schema import UnifiedFinding  # noqa: E402
from engine.ingestion.semgrep_parser import parse_semgrep_json  # noqa: E402
from engine.ingestion.zap_parser import parse_zap_json  # noqa: E402


def _key(item: dict[str, Any]) -> tuple[Any, ...]:
    source = item.get("source")
    if source == "sast":
        return source, item.get("cwe_id"), item.get("file"), item.get("line")
    return source, item.get("cwe_id"), item.get("url"), (item.get("method") or "").upper(), item.get("parameter")


def evaluate(target_id: str, semgrep: Path, zap: Path, manifest: Path) -> dict[str, Any]:
    with manifest.open("r", encoding="utf-8") as handle:
        ground_truth = yaml.safe_load(handle)
    if not isinstance(ground_truth, dict) or ground_truth.get("target_id") != target_id:
        raise ValueError("Ground-truth target_id does not match the selected target")
    actual = [*parse_semgrep_json(semgrep, target_id), *parse_zap_json(zap, target_id)]
    expected_rows = ground_truth.get("findings", [])
    if not isinstance(expected_rows, list):
        raise ValueError("Manifest findings must be a list")
    expected = [dict(row) for row in expected_rows]
    actual_by_key: dict[tuple[Any, ...], list[UnifiedFinding]] = {}
    for finding in actual:
        actual_by_key.setdefault(_key(finding.model_dump()), []).append(finding)
    matched: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    used: set[str] = set()
    for row in expected:
        candidates = actual_by_key.get(_key(row), [])
        finding = next((item for item in candidates if item.id not in used), None)
        if finding is None:
            missing.append(row)
        else:
            used.add(finding.id)
            matched.append({"expected": row, "actual": finding.model_dump(mode="json")})
    false_positives = [finding.model_dump(mode="json") for finding in actual if finding.id not in used]
    tp, fp, fn = len(matched), len(false_positives), len(missing)
    return {
        "target_id": target_id,
        "target_revision": ground_truth.get("target_revision"),
        "ground_truth_kind": ground_truth.get("kind", "unspecified"),
        "counts": {"true_positive": tp, "false_positive": fp, "false_negative": fn},
        "precision": tp / (tp + fp) if tp + fp else 1.0,
        "recall": tp / (tp + fn) if tp + fn else 1.0,
        "matched": matched,
        "false_positives": false_positives,
        "false_negatives": missing,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=("flask_demo", "juice_shop"))
    parser.add_argument("--semgrep", type=Path, required=True)
    parser.add_argument("--zap", type=Path, required=True)
    parser.add_argument("--ground-truth", type=Path)
    args = parser.parse_args()
    manifest = args.ground_truth or ROOT / "data" / "ground_truth" / f"{args.target}.yaml"
    try:
        result = evaluate(args.target, args.semgrep, args.zap, manifest)
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(result["counts"]["false_negative"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
