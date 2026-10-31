from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..ast_mapper.route_schema import RouteNode
from ..code_intelligence.shadow_ranker import (
    GraphCodeBERTShadowRanker,
    MODEL_ID,
    MODEL_REVISION,
    PREPROCESSOR_VERSION,
    TASK_HEAD_VERSION,
    route_candidate_id,
)
from ..ingestion.schema import UnifiedFinding

PLANNER_VERSION = "1.0"
RULE_MAPPING_VERSION = "1.0"
ZAP_RULES_BY_CWE: dict[str, tuple[str, ...]] = {
    "CWE-22": ("6",),
    "CWE-78": ("90020",),
    "CWE-79": ("40012", "40014"),
    "CWE-89": ("40018",),
    "CWE-601": ("20019",),
}
_SEVERITY_ORDER = {
    "CRITICAL": 0,
    "ERROR": 0,
    "HIGH": 1,
    "WARNING": 2,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


@dataclass
class ScanTask:
    task_id: str
    target_id: str
    route_id: str
    raw_url: str
    normalized_url: str
    method: str
    phase: str
    priority_score: int
    reason_codes: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    zap_rule_ids: list[str] = field(default_factory=list)
    excluded_zap_rule_ids: list[str] = field(default_factory=list)
    parameters: list[dict[str, str]] = field(default_factory=list)
    parameter_limitation: str | None = None
    status: str = "QUEUED"
    started_at: str | None = None
    finished_at: str | None = None
    progress: int | None = None
    error: str | None = None


@dataclass
class ScanPlan:
    scan_id: str
    target_id: str
    target_url: str
    planner_version: str
    rule_mapping_version: str
    created_at: str
    deadline_at: str
    targeted_tasks: list[ScanTask]
    broad_tasks: list[ScanTask]
    unresolved_finding_ids: list[str]
    status: str = "PLANNED"
    code_intelligence: dict[str, Any] = field(default_factory=dict)
    intelligence_assessments: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["code_intelligence"] = self.code_intelligence
        payload["intelligence_assessments"] = self.intelligence_assessments
        return payload


def _route_id(route: RouteNode) -> str:
    return route_candidate_id(route)


def _task_id(
    route_id: str,
    method: str,
    phase: str,
    rule_ids: tuple[str, ...] = (),
) -> str:
    identity = "|".join((route_id, method, phase, *rule_ids))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def _parameter_limitation(route: RouteNode) -> str | None:
    unsupported = sorted(
        {
            parameter.source
            for parameter in route.input_parameters
            if parameter.source in {"json", "header"}
        }
    )
    if not unsupported:
        return None
    return (
        "ZAP scan API cannot bind these AST inputs directly: "
        + ", ".join(unsupported)
    )


def _matching_findings(
    route: RouteNode,
    findings: list[UnifiedFinding],
) -> list[UnifiedFinding]:
    return [
        finding
        for finding in findings
        if finding.source == "sast"
        and finding.target_id == route.target_id
        and route.contains_location(finding.file, finding.line)
    ]


def _scope_matches(finding: UnifiedFinding, scope) -> bool:
    return (
        finding.file is not None
        and finding.line is not None
        and scope.file == finding.file
        and scope.start_line <= finding.line <= scope.end_line
    )


def _normalized_handler_name(route: RouteNode) -> tuple[str, ...]:
    names = set()
    if route.handler:
        names.add(route.handler)
        names.add(route.handler.rsplit(".", 1)[-1])
        if route.handler.startswith("."):
            names.add(route.handler.lstrip("."))
    return tuple(sorted({name for name in names if name}))


def _task_priority(
    route: RouteNode,
    matching: list[UnifiedFinding],
    routes: list[RouteNode],
) -> tuple[int, list[str]]:
    exact_scope = any(
        route.scopes
        and any(
            _scope_matches(finding, scope)
            and (scope.function in _normalized_handler_name(route) or scope.function == route.handler)
            for scope in route.scopes
        )
        for finding in matching
    )
    helper_scope = any(
        route.scopes
        and any(
            _scope_matches(finding, scope)
            and scope.function not in _normalized_handler_name(route)
            and scope.function != route.handler
            for scope in route.scopes
        )
        for finding in matching
    )
    supported_inputs = any(
        parameter.source in {"path", "query", "form"}
        for parameter in route.input_parameters
    )
    has_multiple_candidates = any(
        sum(
            candidate.target_id == finding.target_id
            and candidate.resolved
            and candidate.contains_location(finding.file, finding.line)
            for candidate in routes
        )
        > 1
        for finding in matching
    )
    if has_multiple_candidates:
        return 3, ["SAST_CWE_MATCH", "MULTIPLE_ROUTE_CANDIDATES"]
    if exact_scope and supported_inputs:
        return 0, ["SAST_CWE_MATCH", "ROUTE_SCOPE_MATCH", "PARAMETER_SURFACE_MATCH"]
    if helper_scope and supported_inputs:
        return 1, ["SAST_CWE_MATCH", "HELPER_SCOPE_MATCH", "PARAMETER_SURFACE_MATCH"]
    if matching:
        return 2, ["SAST_CWE_MATCH", "ROUTE_SCOPE_MATCH", "INPUT_EVIDENCE_INCOMPLETE"]
    return 4, ["BROAD_COVERAGE"]


def _shadow_rank_candidates(
    scan_id: str,
    target_id: str,
    findings: list[UnifiedFinding],
    routes: list[RouteNode],
    *,
    model_mode: str = "OFF",
    source_revision: str | None = None,
    source_root: Path | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    mode = str(model_mode or "OFF").upper()
    metadata: dict[str, Any] = {
        "mode": mode,
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "task_head_version": TASK_HEAD_VERSION,
        "preprocessor_version": PREPROCESSOR_VERSION,
        "status": "SKIPPED",
        "score_calibration": "UN_CALIBRATED",
        "enabled": mode != "OFF",
    }
    if mode == "OFF":
        return metadata, []

    ranker = GraphCodeBERTShadowRanker(
        mode=mode,
        source_revision=source_revision,
        enabled=True,
        source_root=source_root,
    )
    assessments = ranker.assess_candidates(scan_id, target_id, findings, routes)
    if not assessments:
        return metadata, []

    metadata["status"] = (
        "ERROR"
        if any(item.status == "ERROR" for item in assessments)
        else "AVAILABLE"
        if any(item.status == "AVAILABLE" for item in assessments)
        else "SKIPPED"
    )
    metadata["score_calibration"] = "UN_CALIBRATED"
    metadata["status_detail"] = (
        "Pinned GraphCodeBERT inference ranks deterministic ambiguous candidates; "
        "its uncalibrated score is advisory only."
    )
    return metadata, [assessment.to_dict() for assessment in assessments]


def build_scan_plan(
    target_id: str,
    target_url: str,
    findings: list[UnifiedFinding],
    routes: list[RouteNode],
    *,
    budget_minutes: int = 5,
    model_mode: str = "OFF",
    source_revision: str | None = None,
    source_root: Path | None = None,
    deadline_at: str | None = None,
) -> ScanPlan:
    if not 1 <= budget_minutes <= 30:
        raise ValueError("budget_minutes must be between 1 and 30")
    if not target_id or not target_url:
        raise ValueError("target_id and target_url are required")
    if any(route.target_id != target_id for route in routes):
        raise ValueError("Route inventory contains a different target_id")
    if any(finding.target_id != target_id for finding in findings):
        raise ValueError("Semgrep findings contain a different target_id")

    created = datetime.now(timezone.utc)
    scan_id = str(uuid4())
    code_intelligence, intelligence_assessments = _shadow_rank_candidates(
        scan_id,
        target_id,
        findings,
        routes,
        model_mode=model_mode,
        source_revision=source_revision,
        source_root=source_root,
    )
    model_scores = {
        (item["finding_id"], item["candidate_route_id"]): float(item["relevance_score"])
        for item in intelligence_assessments
        if item.get("status") == "AVAILABLE"
    }
    targeted_by_key: dict[tuple[str, str, str], ScanTask] = {}
    broad_tasks: list[ScanTask] = []
    mapped_finding_ids: set[str] = set()

    for route in routes:
        if not route.resolved:
            continue
        route_id = _route_id(route)
        matching = _matching_findings(route, findings)
        if matching:
            mapped_finding_ids.update(finding.id for finding in matching)
        priority_class, base_reasons = _task_priority(route, matching, routes)

        supported_findings = [
            finding
            for finding in matching
            if ZAP_RULES_BY_CWE.get(finding.cwe_id)
        ]
        methods = sorted({method.upper() for method in route.methods})
        if supported_findings:
            for method in methods:
                for finding in supported_findings:
                    rule_ids = ZAP_RULES_BY_CWE[finding.cwe_id]
                    key = (route_id, method, "ALL_TARGETED_RULES")
                    task = targeted_by_key.get(key)
                    if task is None:
                        finding_priority = _SEVERITY_ORDER.get(
                            finding.severity.upper(), 5
                        )
                        task = ScanTask(
                            task_id=_task_id(route_id, method, "TARGETED", rule_ids),
                            target_id=target_id,
                            route_id=route_id,
                            raw_url=route.raw_url,
                            normalized_url=route.normalized_url,
                            method=method,
                            phase="TARGETED",
                            priority_score=priority_class * 100 + finding_priority * 10,
                            reason_codes=list(base_reasons),
                            zap_rule_ids=[],
                            parameters=[
                                {"name": parameter.name, "source": parameter.source}
                                for parameter in route.input_parameters
                            ],
                            parameter_limitation=_parameter_limitation(route),
                        )
                        targeted_by_key[key] = task
                    if finding.id not in task.finding_ids:
                        task.finding_ids.append(finding.id)
                    task.zap_rule_ids = sorted(set(task.zap_rule_ids) | set(rule_ids))
                    model_score = model_scores.get((finding.id, route_id))
                    if model_score is not None and priority_class == 3:
                        if "GRAPHCODEBERT_TIEBREAK" not in task.reason_codes:
                            task.reason_codes.append("GRAPHCODEBERT_TIEBREAK")
                    model_tiebreak = (
                        9 - min(9, int(model_score * 10))
                        if model_score is not None and priority_class == 3
                        else 0
                    )
                    task.priority_score = min(
                        task.priority_score,
                        priority_class * 100
                        + _SEVERITY_ORDER.get(finding.severity.upper(), 5) * 10
                        + model_tiebreak,
                    )
                    for reason in base_reasons:
                        if reason not in task.reason_codes:
                            task.reason_codes.append(reason)

        targeted_rule_ids = {
            rule_id
            for task in targeted_by_key.values()
            if task.route_id == route_id
            for rule_id in task.zap_rule_ids
        }
        for method in methods:
            broad_tasks.append(
                ScanTask(
                    task_id=_task_id(route_id, method, "BROAD"),
                    target_id=target_id,
                    route_id=route_id,
                    raw_url=route.raw_url,
                    normalized_url=route.normalized_url,
                    method=method,
                    phase="BROAD",
                    priority_score=400,
                    reason_codes=["BROAD_COVERAGE"],
                    excluded_zap_rule_ids=sorted(targeted_rule_ids),
                    parameters=[
                        {"name": parameter.name, "source": parameter.source}
                        for parameter in route.input_parameters
                    ],
                    parameter_limitation=_parameter_limitation(route),
                )
            )

    for task in targeted_by_key.values():
        task.task_id = _task_id(
            task.route_id,
            task.method,
            "TARGETED",
            tuple(sorted(task.zap_rule_ids)),
        )

    targeted = sorted(
        targeted_by_key.values(),
        key=lambda task: (task.priority_score, task.normalized_url, task.method, task.task_id),
    )
    broad_tasks.sort(
        key=lambda task: (task.normalized_url, task.method, task.task_id)
    )
    sast_ids = {finding.id for finding in findings if finding.source == "sast"}
    if deadline_at is None:
        final_deadline = created + timedelta(minutes=budget_minutes)
    else:
        final_deadline = datetime.fromisoformat(deadline_at)
        if final_deadline.tzinfo is None:
            raise ValueError("deadline_at must include a timezone")
    return ScanPlan(
        scan_id=scan_id,
        target_id=target_id,
        target_url=target_url,
        planner_version=PLANNER_VERSION,
        rule_mapping_version=RULE_MAPPING_VERSION,
        created_at=created.isoformat(),
        deadline_at=final_deadline.astimezone(timezone.utc).isoformat(),
        targeted_tasks=targeted,
        broad_tasks=broad_tasks,
        unresolved_finding_ids=sorted(sast_ids - mapped_finding_ids),
        code_intelligence=code_intelligence,
        intelligence_assessments=intelligence_assessments,
    )
