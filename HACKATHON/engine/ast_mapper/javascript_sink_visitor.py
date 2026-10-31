from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .route_schema import CodeScope
from .sink_detector import SINK_CWE_MAP, SinkFinding


def find_javascript_sinks(
    source_dir: str | Path, target_id: str
) -> list[SinkFinding]:
    bridge = Path(__file__).with_name("javascript_sink_bridge.js")
    result = subprocess.run(
        ["node", str(bridge), str(Path(source_dir).resolve())],
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    records = json.loads(result.stdout)
    if not isinstance(records, list):
        raise ValueError("JavaScript sink bridge output must be a JSON array")
    findings: list[SinkFinding] = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("JavaScript sink bridge returned a malformed record")
        sink_type = record["sink_type"]
        findings.append(
            SinkFinding(
                target_id=target_id,
                cwe_id=SINK_CWE_MAP[sink_type],
                sink_type=sink_type,
                scope=CodeScope(
                    file=record["file"],
                    start_line=record["start_line"],
                    end_line=record["end_line"],
                    function=record["function"],
                ),
                line=record["line"],
                evidence=record["evidence"],
            )
        )
    return findings
