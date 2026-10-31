from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CodeContextAssessment:
    assessment_id: str
    scan_id: str
    target_id: str
    finding_id: str
    candidate_route_id: str
    model_id: str = "microsoft/graphcodebert-base"
    model_revision: str = "9b8660679da59fe3e7423b03efa48d41944eec42"
    task_head_version: str = "cosine-retrieval-v1"
    preprocessor_version: str = "lexical-dataflow-graph-mask-v1"
    source_revision: str | None = None
    status: str = "SKIPPED"
    relevance_score: float = 0.0
    score_calibration: str = "UN_CALIBRATED"
    evidence_refs: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    mode: str = "SHADOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "scan_id": self.scan_id,
            "target_id": self.target_id,
            "finding_id": self.finding_id,
            "candidate_route_id": self.candidate_route_id,
            "model_id": self.model_id,
            "model_revision": self.model_revision,
            "task_head_version": self.task_head_version,
            "preprocessor_version": self.preprocessor_version,
            "source_revision": self.source_revision,
            "status": self.status,
            "relevance_score": self.relevance_score,
            "score_calibration": self.score_calibration,
            "evidence_refs": self.evidence_refs,
            "limitations": self.limitations,
            "mode": self.mode,
        }
