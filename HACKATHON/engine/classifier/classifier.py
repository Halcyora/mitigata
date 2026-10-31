from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Literal

from ..ingestion.schema import UnifiedFinding

VerificationLabel = Literal[
    "Confirmed", "Code only", "Runtime only", "UNVERIFIED"
]


class ClassificationError(ValueError):
    """Raised when classification inputs are outside the supported contract."""


class Label(str, Enum):
    CONFIRMED = "Confirmed"
    CODE_ONLY = "Code only"
    RUNTIME_ONLY = "Runtime only"


@dataclass(frozen=True)
class ClassificationResult:
    label: Label
    confidence: float
    reason: str


def classify(
    ast_reachable: bool | None,
    langgraph_label: VerificationLabel | None,
    is_config_only: bool,
    dual_confirmed: bool = False,
) -> ClassificationResult:
    """Classify a finding using the Phase 5 priority order and confidence values."""
    if ast_reachable is not None and not isinstance(ast_reachable, bool):
        raise ClassificationError("ast_reachable must be True, False, or None")
    if not isinstance(is_config_only, bool):
        raise ClassificationError("is_config_only must be a bool")
    if not isinstance(dual_confirmed, bool):
        raise ClassificationError("dual_confirmed must be a bool")
    if langgraph_label not in {
        None,
        "Confirmed",
        "Code only",
        "Runtime only",
        "UNVERIFIED",
    }:
        raise ClassificationError(
            f"Unsupported verification label: {langgraph_label!r}"
        )

    if langgraph_label == "Confirmed" and dual_confirmed:
        return ClassificationResult(
            label=Label.CONFIRMED,
            confidence=0.98,
            reason=(
                "SAST sink and DAST probe both confirmed; CWE and route both match."
            ),
        )
    if langgraph_label == "Confirmed":
        return ClassificationResult(
            label=Label.CONFIRMED,
            confidence=0.90,
            reason="Runtime probe confirmed exploitation evidence in the HTTP response.",
        )
    if is_config_only:
        return ClassificationResult(
            label=Label.RUNTIME_ONLY,
            confidence=0.85,
            reason=(
                "No code sink; runtime misconfiguration only "
                "(for example, missing headers, CORS, or TLS controls)."
            ),
        )
    if ast_reachable is False:
        return ClassificationResult(
            label=Label.CODE_ONLY,
            confidence=0.95,
            reason=(
                "Sink exists in unreachable code; no discovered HTTP route reaches "
                "this function."
            ),
        )
    if ast_reachable is True:
        return ClassificationResult(
            label=Label.CODE_ONLY,
            confidence=0.70,
            reason=(
                "A discovered route reaches the sink, but runtime verification "
                "was inconclusive."
            ),
        )
    return ClassificationResult(
        label=Label.CODE_ONLY,
        confidence=0.50,
        reason="AST reachability is unknown; classified conservatively.",
    )


def apply_classification(
    finding: UnifiedFinding,
    *,
    langgraph_label: VerificationLabel | None = None,
    is_config_only: bool = False,
    dual_confirmed: bool = False,
) -> UnifiedFinding:
    """Return a finding with Phase 5 label/confidence while preserving its evidence."""
    result = classify(
        ast_reachable=finding.reachable,
        langgraph_label=langgraph_label,
        is_config_only=is_config_only,
        dual_confirmed=dual_confirmed,
    )
    return finding.model_copy(
        update={"label": result.label.value, "confidence": result.confidence}
    )


def sort_findings(findings: Iterable[UnifiedFinding]) -> list[UnifiedFinding]:
    """Return findings in classifier priority order, preserving ties."""
    priority = {
        "Confirmed": 0,
        "Corroborated": 1,
        "Code only": 2,
        "Runtime only": 3,
    }
    return sorted(
        findings,
        key=lambda finding: priority.get(finding.label or "Code only", 2),
    )
