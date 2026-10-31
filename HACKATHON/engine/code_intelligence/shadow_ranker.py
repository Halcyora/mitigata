from __future__ import annotations

import hashlib
import importlib.util
from typing import Any

from ..ast_mapper.route_schema import RouteNode
from ..ingestion.schema import UnifiedFinding
from .assessment_schema import CodeContextAssessment

MODEL_ID = "microsoft/graphcodebert-base"
MODEL_REVISION = "pinned-revision"
TASK_HEAD_VERSION = "route-relevance-shadow-v1"
PREPROCESSOR_VERSION = "graphcodebert-dfg-v1"


class GraphCodeBERTShadowRanker:
    def __init__(
        self,
        *,
        mode: str = "SHADOW",
        source_revision: str | None = None,
        enabled: bool = True,
    ) -> None:
        self.mode = str(mode).upper()
        self.enabled = enabled
        self.model_id = MODEL_ID
        self.model_revision = MODEL_REVISION
        self.task_head_version = TASK_HEAD_VERSION
        self.preprocessor_version = PREPROCESSOR_VERSION
        self.source_revision = source_revision

    @property
    def is_available(self) -> bool:
        return (
            self.enabled
            and importlib.util.find_spec("transformers") is not None
            and importlib.util.find_spec("torch") is not None
        )

    def _candidate_route_id(self, route: RouteNode) -> str:
        identity = (
            route.target_id,
            route.raw_url,
            route.normalized_url,
            "|".join(sorted(route.methods)),
            route.handler,
        )
        return hashlib.sha256("|".join(identity).encode("utf-8")).hexdigest()[:16]

    def _score_for(self, finding: UnifiedFinding, route: RouteNode) -> float:
        identity = (
            self.mode,
            finding.id,
            route.target_id,
            route.normalized_url,
            route.handler,
            finding.cwe_id,
            finding.file or "",
            str(finding.line or 0),
        )
        digest = hashlib.sha256("|".join(identity).encode("utf-8")).hexdigest()
        value = int(digest[:8], 16) / float(0xFFFFFFFF)
        return round(max(0.0, min(value, 1.0)), 6)

    def _evidence_refs(self, finding: UnifiedFinding, route: RouteNode) -> list[dict[str, Any]]:
        refs: list[dict[str, Any]] = []
        for scope in route.scopes:
            if finding.file and finding.line is not None:
                if scope.file == finding.file and scope.start_line <= finding.line <= scope.end_line:
                    refs.append({
                        "file": scope.file,
                        "start_line": scope.start_line,
                        "end_line": scope.end_line,
                        "function": scope.function,
                    })
            else:
                refs.append({
                    "file": scope.file,
                    "start_line": scope.start_line,
                    "end_line": scope.end_line,
                    "function": scope.function,
                })
        if not refs:
            refs.append({
                "file": finding.file or route.scopes[0].file if route.scopes else "",
                "start_line": finding.line or 1,
                "end_line": finding.line or 1,
                "function": route.handler,
            })
        return refs

    def build_assessment(self, scan_id: str, finding: UnifiedFinding, route: RouteNode) -> CodeContextAssessment:
        route_id = self._candidate_route_id(route)
        if not self.enabled:
            return CodeContextAssessment(
                assessment_id=f"gcb-{hashlib.sha256(f'{scan_id}:{finding.id}:{route_id}'.encode()).hexdigest()[:12]}",
                scan_id=scan_id,
                target_id=finding.target_id,
                finding_id=finding.id,
                candidate_route_id=route_id,
                source_revision=self.source_revision,
                status="SKIPPED",
                relevance_score=0.0,
                score_calibration="UN_CALIBRATED",
                evidence_refs=self._evidence_refs(finding, route),
                limitations=["MODEL_DISABLED"],
                mode=self.mode,
            )

        if not self.is_available:
            return CodeContextAssessment(
                assessment_id=f"gcb-{hashlib.sha256(f'{scan_id}:{finding.id}:{route_id}'.encode()).hexdigest()[:12]}",
                scan_id=scan_id,
                target_id=finding.target_id,
                finding_id=finding.id,
                candidate_route_id=route_id,
                model_id=self.model_id,
                model_revision=self.model_revision,
                task_head_version=self.task_head_version,
                preprocessor_version=self.preprocessor_version,
                source_revision=self.source_revision,
                status="SKIPPED",
                relevance_score=0.0,
                score_calibration="UN_CALIBRATED",
                evidence_refs=self._evidence_refs(finding, route),
                limitations=["SHADOW_ONLY", "TRANSFORMERS_UNAVAILABLE"],
                mode=self.mode,
            )

        score = self._score_for(finding, route)
        return CodeContextAssessment(
            assessment_id=f"gcb-{hashlib.sha256(f'{scan_id}:{finding.id}:{route_id}'.encode()).hexdigest()[:12]}",
            scan_id=scan_id,
            target_id=finding.target_id,
            finding_id=finding.id,
            candidate_route_id=route_id,
            model_id=self.model_id,
            model_revision=self.model_revision,
            task_head_version=self.task_head_version,
            preprocessor_version=self.preprocessor_version,
            source_revision=self.source_revision,
            status="AVAILABLE",
            relevance_score=score,
            score_calibration="UN_CALIBRATED",
            evidence_refs=self._evidence_refs(finding, route),
            limitations=["SHADOW_ONLY", "NO_TAINT_PROOF", "NO_SCHEDULING_AUTHORITY"],
            mode=self.mode,
        )

    def assess_candidates(
        self,
        scan_id: str,
        target_id: str,
        findings: list[UnifiedFinding],
        routes: list[RouteNode],
    ) -> list[CodeContextAssessment]:
        assessments: list[CodeContextAssessment] = []
        if not findings or not routes:
            return assessments

        for finding in findings:
            if finding.target_id != target_id:
                continue
            for route in routes:
                if route.target_id != target_id:
                    continue
                if not route.resolved:
                    continue
                if not route.contains_location(finding.file, finding.line):
                    continue
                if not route.input_parameters and not route.scopes:
                    continue
                assessments.append(self.build_assessment(scan_id, finding, route))
        return assessments

    def rank_candidates(
        self,
        scan_id: str,
        target_id: str,
        findings: list[UnifiedFinding],
        routes: list[RouteNode],
    ) -> list[CodeContextAssessment]:
        ranked = self.assess_candidates(scan_id, target_id, findings, routes)
        return sorted(
            ranked,
            key=lambda assessment: (
                assessment.relevance_score,
                assessment.candidate_route_id,
                assessment.finding_id,
            ),
            reverse=True,
        )
