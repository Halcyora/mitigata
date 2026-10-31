from __future__ import annotations

from typing import Literal

Label = Literal["Confirmed", "Code only", "Runtime only"]


def classify(findings: list[dict]) -> list[dict]:
    """Placeholder classifier that preserves finding order while enabling target-specific logic later."""
    for finding in findings:
        finding.setdefault("label", "Code only")
    return findings
