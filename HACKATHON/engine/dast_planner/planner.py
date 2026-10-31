from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from ..ast_mapper.route_schema import RouteNode
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

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _route_id(route: RouteNode) -> str:
    identity = (
        f"{route.target_id}|{route.raw_url}|{','.join(sorted(route.methods))}|"
        f"{route.handler}|{route.scopes[0].file if route.scopes else ''}"
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def _task_id(
    route_id: str,
    method: str,
    phase: str,
    rule_ids: tuple[str, ...] = (),
) -> str:
    identity = "|".join((route_id, method, phase, *rule_ids))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


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


def _task_priority(
    route: RouteNode,
    matching: list[UnifiedFinding],
    routes: list[RouteNode],
) -> tuple[int, list[str]]:
    is_exact_scope = any(
        route.scopes
        and finding.file == route.scopes[0].file
        and finding.line is not None
        and route.scopes[0].start_line <= finding.line <= route.scopes[0].end_line
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
        return 3, ["MULTIPLE_ROUTE_CANDIDATES"]
    if is_exact_scope and supported_inputs:
        return 0, ["SAST_CWE_MATCH", "ROUTE_SCOPE_MATCH", "PARAMETER_SURFACE_MATCH"]
    if not is_exact_scope and supported_inputs:
        return 1, ["SAST_CWE_MATCH", "HELPER_SCOPE_MATCH", "PARAMETER_SURFACE_MATCH"]
    if matching:
        return 2, ["SAST_CWE_MATCH", "ROUTE_SCOPE_MATCH", "INPUT_EVIDENCE_INCOMPLETE"]
    return 4, ["BROAD_COVERAGE"]


def build_scan_plan(
    target_id: str,
    target_url: str,
    findings: list[UnifiedFinding],
    routes: list[RouteNode],
    *,
    budget_minutes: int = 5,
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
                    key = (route_id, method, ",".join(rule_ids))
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
                            priority_score=priority_class * 100 + finding_priority,
                            reason_codes=list(base_reasons),
                            zap_rule_ids=list(rule_ids),
                            parameters=[
                                {"name": parameter.name, "source": parameter.source}
                                for parameter in route.input_parameters
                            ],
                        )
                        targeted_by_key[key] = task
                    if finding.id not in task.finding_ids:
                        task.finding_ids.append(finding.id)
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
                )
            )

    targeted = sorted(
        targeted_by_key.values(),
        key=lambda task: (task.priority_score, task.normalized_url, task.method, task.task_id),
    )
    broad_tasks.sort(
        key=lambda task: (task.normalized_url, task.method, task.task_id)
    )
    sast_ids = {finding.id for finding in findings if finding.source == "sast"}
    return ScanPlan(
        scan_id=str(uuid4()),
        target_id=target_id,
        target_url=target_url,
        planner_version=PLANNER_VERSION,
        rule_mapping_version=RULE_MAPPING_VERSION,
        created_at=created.isoformat(),
        deadline_at=(created + timedelta(minutes=budget_minutes)).isoformat(),
        targeted_tasks=targeted,
        broad_tasks=broad_tasks,
        unresolved_finding_ids=sorted(sast_ids - mapped_finding_ids),
    )
