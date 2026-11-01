from __future__ import annotations

import hashlib
import ast
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse
from uuid import NAMESPACE_URL, uuid5

import yaml
from pydantic import BaseModel, Field

from ..adapters.base import TargetProfile
from ..ast_mapper.call_graph import build_call_graph
from ..ast_mapper.merger import enrich_findings_with_ast
from ..ast_mapper.route_schema import RouteNode
from ..classifier.classifier import sort_findings
from ..classifier.classifier import calculate_issue_risk_score
from ..ingestion.correlator import correlate_and_merge
from ..ingestion.schema import UnifiedFinding
from ..ingestion.semgrep_parser import parse_semgrep_json
from ..ingestion.zap_parser import parse_zap_json
from ..verification_store import load_confirmed_results
from ..verification.profile import load_target_profile

logger = logging.getLogger(__name__)

TargetId = Literal["flask_demo", "juice_shop"]
NodeType = Literal["endpoint", "controller", "sink", "evidence", "suppressed"]
FindingLabel = Literal["Confirmed", "Corroborated", "Code only", "Runtime only"]
_CACHE_TTL_SECONDS = 10.0
_CACHE: dict[str, tuple[float, GraphSnapshot]] = {}
_CACHE_LOCK = threading.Lock()


class GraphNodeData(BaseModel):
    label: str
    target_id: str
    finding_id: str | None = None
    finding_label: FindingLabel | None = None
    confidence: float | None = None
    file: str | None = None
    line: int | None = None
    routes: list[str] = Field(default_factory=list)
    mapped_urls: list[str] = Field(default_factory=list)
    cwe: str | None = None
    evidence: str | None = None
    evidence_items: list[dict[str, object]] = Field(default_factory=list)
    payload: str | None = None
    risk_score: int | None = None
    merged_from: list[str] = Field(default_factory=list)
    reason: str | None = None
    url: str | None = None
    method: str | None = None
    parameter: str | None = None
    parameter_source: str | None = None
    http_status: int | None = None
    severity: str | None = None
    source: str | None = None
    source_snippet: str | None = None
    sink_type: str | None = None
    function: str | None = None
    remediation: str | None = None


_REMEDIATION_BY_CWE = {
    "CWE-89": "Use a parameterized query and pass user input as bound values; avoid building SQL with string concatenation or formatting.",
    "CWE-79": "Keep untrusted input as template data and rely on context-aware output escaping; avoid marking user input as safe HTML.",
    "CWE-78": "Avoid shell execution. Call a fixed executable with an argument list, validate inputs, and set a timeout.",
    "CWE-22": "Resolve paths beneath an approved base directory and reject paths that escape it after normalization.",
    "CWE-601": "Allow redirects only to approved relative paths or an explicit allowlist of trusted hosts.",
    "CWE-798": "Move the credential to a secret manager or environment configuration, then rotate the exposed value.",
    "CWE-94": "Use fixed, application-controlled templates or expressions; pass user input as data rather than executable template text.",
    "CWE-95": "Remove dynamic evaluation and parse only the required input format with a strict allowlist.",
    "CWE-502": "Use a data-only serialization format and validate the decoded data against a schema.",
    "CWE-347": "Require a high-entropy signing key and explicitly allow only the expected JWT algorithm, issuer, and audience.",
}


def _static_sql(node: ast.AST) -> bool:
    value: ast.AST = node
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "text"
        and len(node.args) == 1
    ):
        value = node.args[0]
    return isinstance(value, ast.Constant) and isinstance(value.value, str)


def _sql_has_bind_marker(node: ast.AST) -> bool:
    value = node.args[0] if isinstance(node, ast.Call) else node
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return False
    return bool(re.search(r"\?|%s|%\([A-Za-z_]\w*\)s|:[A-Za-z_]\w*|\$\d+", value.value))


def _has_bound_sql_parameters(finding: UnifiedFinding, source_root: Path | None) -> bool:
    """Suppress only a direct execute call with a static query and explicit bind values."""
    if (
        finding.cwe_id != "CWE-89"
        or finding.source != "sast"
        or not finding.file
        or not finding.line
        or source_root is None
    ):
        return False
    source_path = (source_root / finding.file).resolve()
    if not source_path.is_relative_to(source_root) or not source_path.is_file():
        return False
    try:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        return False
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and node.lineno == finding.line
            and len(node.args) >= 2
            and _static_sql(node.args[0])
            and _sql_has_bind_marker(node.args[0])
            and isinstance(node.args[1], (ast.Tuple, ast.List, ast.Dict, ast.Name))
        ):
            return True
    return False


def _source_excerpt(finding: UnifiedFinding, source_root: Path | None) -> str | None:
    """Return a small numbered source excerpt for the selected target finding."""
    if source_root is None or not finding.file or not finding.line:
        return None
    candidate = (source_root / finding.file).resolve()
    if not candidate.is_relative_to(source_root) or not candidate.is_file():
        return None
    try:
        lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    start = max(0, finding.line - 4)
    end = min(len(lines), finding.line + 3)
    return "\n".join(f"{number + 1}: {lines[number]}" for number in range(start, end))


class GraphNode(BaseModel):
    id: str
    type: NodeType
    position: dict[str, float]
    data: GraphNodeData


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    animated: bool = False


class GraphStats(BaseModel):
    target_id: TargetId
    total: int
    confirmed: int
    corroborated: int
    code_only: int
    runtime_only: int
    suppression_ratio: float = Field(ge=0.0, le=1.0)
    cwe_types_covered: list[str]


class GraphResponse(BaseModel):
    target_id: TargetId
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    stats: GraphStats


@dataclass(frozen=True)
class GraphSnapshot:
    response: GraphResponse
    findings: tuple[UnifiedFinding, ...]


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _config_path(target_id: str) -> Path:
    config_dir = Path(
        os.environ.get(
            "MITIGATA_CONFIG_DIR", str(_repository_root() / "configs")
        )
    ).expanduser()
    path = (config_dir / f"{target_id}.yaml").resolve()
    if path.parent != config_dir.resolve() or not path.is_file():
        raise FileNotFoundError(f"Target profile not found for {target_id!r}")
    return path


def _profile_data(target_id: str) -> dict[str, object]:
    path = _config_path(target_id)
    with path.open("r", encoding="utf-8") as handle:
        profile = yaml.safe_load(handle)
    if not isinstance(profile, dict) or profile.get("target_id") != target_id:
        raise ValueError(f"Target profile {target_id!r} is malformed")
    return profile


def _source_dir(raw_source_dir: object) -> Path | None:
    if not isinstance(raw_source_dir, str) or not raw_source_dir.strip():
        raise ValueError("Target profile must define source_dir")
    repo_root = _repository_root()
    if raw_source_dir.startswith("/targets/"):
        relative = raw_source_dir.removeprefix("/targets/")
        candidates = [Path("/targets") / relative, repo_root / "targets" / relative]
    else:
        path = Path(raw_source_dir)
        candidates = [path if path.is_absolute() else repo_root / path]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    return None


def _report_path(target_id: str, scanner: Literal["semgrep", "zap"]) -> Path | None:
    root = _repository_root()
    for directory in ("raw", "sample"):
        candidate = root / "data" / directory / f"{target_id}-{scanner}.json"
        if directory == "sample":
            candidate = root / "data" / directory / f"{target_id}_{scanner}.json"
        if candidate.is_file():
            return candidate
    return None


def _stable_findings(
    findings: list[UnifiedFinding], target_id: str
) -> list[UnifiedFinding]:
    stable: list[UnifiedFinding] = []
    for index, finding in enumerate(findings):
        identity = {
            "target_id": target_id,
            "source": finding.source,
            "index": index,
            "rule_id": finding.rule_id,
            "cwe_id": finding.cwe_id,
            "file": finding.file,
            "line": finding.line,
            "url": finding.url,
            "method": finding.method,
            "parameter": finding.parameter,
        }
        fingerprint = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        finding_id = str(uuid5(NAMESPACE_URL, f"mitigata:{fingerprint}"))
        stable.append(finding.model_copy(update={"id": finding_id}))
    return stable


def _load_findings(target_id: str) -> tuple[list[UnifiedFinding], list[UnifiedFinding]]:
    semgrep_path = _report_path(target_id, "semgrep")
    zap_path = _report_path(target_id, "zap")
    sast = (
        parse_semgrep_json(semgrep_path, target_id)
        if semgrep_path
        else []
    )
    dast = parse_zap_json(zap_path, target_id) if zap_path else []
    return _stable_findings(sast, target_id), _stable_findings(dast, target_id)


def _routes_and_stats(
    target_id: str, profile: dict[str, object]
) -> tuple[list[RouteNode], dict[str, int | float]]:
    source_dir = _source_dir(profile.get("source_dir"))
    if source_dir is None:
        logger.warning(
            "Source directory is unavailable for target %s; graph will omit routes",
            target_id,
        )
        return [], {"suppression_ratio": 0.0}
    language = profile.get("language")
    framework = profile.get("framework")
    if not isinstance(language, str) or not isinstance(framework, str):
        raise ValueError(f"Target profile {target_id!r} lacks adapter metadata")
    call_graph = build_call_graph(
        TargetProfile(
            target_id=target_id,
            language=language,
            framework=framework,
            source_dir=source_dir,
        )
    )
    routes = call_graph.get("routes")
    stats = call_graph.get("stats")
    if not isinstance(routes, list) or not all(
        isinstance(route, RouteNode) for route in routes
    ):
        raise ValueError("Route mapper returned invalid route data")
    if not isinstance(stats, dict):
        raise ValueError("Route mapper returned invalid coverage statistics")
    return routes, stats


def _route_nodes(
    target_id: str, routes: list[RouteNode]
) -> tuple[list[GraphNode], list[GraphEdge], dict[int, tuple[str, str]]]:
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    route_ids: dict[int, tuple[str, str]] = {}
    for index, route in enumerate(routes):
        key = hashlib.sha1(
            f"{route.raw_url}|{','.join(route.methods)}|{route.handler}|{index}".encode()
        ).hexdigest()[:12]
        endpoint_id = f"endpoint:{target_id}:{key}"
        controller_id = f"controller:{target_id}:{key}"
        route_ids[index] = (endpoint_id, controller_id)
        nodes.extend(
            [
                GraphNode(
                    id=endpoint_id,
                    type="endpoint",
                    position={"x": 0.0, "y": 0.0},
                    data=GraphNodeData(
                        label=f"{','.join(route.methods)} {route.normalized_url}",
                        target_id=target_id,
                    ),
                ),
                GraphNode(
                    id=controller_id,
                    type="controller",
                    position={"x": 0.0, "y": 0.0},
                    data=GraphNodeData(
                        label=route.handler,
                        target_id=target_id,
                        file=route.scopes[0].file if route.scopes else None,
                        line=route.scopes[0].start_line if route.scopes else None,
                    ),
                ),
            ]
        )
        edges.append(
            GraphEdge(
                id=f"edge:{endpoint_id}:{controller_id}",
                source=endpoint_id,
                target=controller_id,
            )
        )
    return nodes, edges, route_ids


def _finding_route_indices(
    finding: UnifiedFinding, routes: list[RouteNode]
) -> list[int]:
    if finding.source == "sast":
        return [
            index
            for index, route in enumerate(routes)
            if route.resolved and route.contains_location(finding.file, finding.line)
        ]
    if finding.routes:
        route_paths = set(finding.routes)
        return [
            index
            for index, route in enumerate(routes)
            if route.resolved and route.normalized_url in route_paths
        ]
    if not finding.url:
        return []
    path = urlparse(finding.url).path
    return [
        index
        for index, route in enumerate(routes)
        if route.matches_path(path) and route.matches_method(finding.method)
    ]


def _seed_node_positions(nodes: list[GraphNode]) -> list[GraphNode]:
    layer_by_type = {
        "endpoint": 0,
        "controller": 1,
        "sink": 2,
        "suppressed": 2,
        "evidence": 3,
    }
    positioned: list[GraphNode] = []
    for layer in range(4):
        layer_nodes = [node for node in nodes if layer_by_type[node.type] == layer]
        midpoint = (len(layer_nodes) - 1) / 2
        positioned.extend(
            node.model_copy(
                update={
                    "position": {
                        "x": (index - midpoint) * 280.0,
                        "y": layer * 180.0,
                    }
                }
            )
            for index, node in enumerate(layer_nodes)
        )
    return positioned


def _build_snapshot(target_id: TargetId) -> GraphSnapshot:
    profile = _profile_data(target_id)
    source_root = _source_dir(profile.get("source_dir"))
    try:
        target_origin = load_target_profile(target_id).origin.rstrip("/")
    except (OSError, ValueError, yaml.YAMLError):
        raw_origin = profile.get("target_url")
        target_origin = raw_origin.rstrip("/") if isinstance(raw_origin, str) else ""
    routes, route_stats = _routes_and_stats(target_id, profile)
    sast, dast = _load_findings(target_id)
    # Semgrep can report a dangerous SQL API even when the query is static and
    # all values are bound separately. Remove only that positively identified
    # safe shape; unknown or dynamic query construction remains reportable.
    sast = [
        finding
        for finding in sast
        if not _has_bound_sql_parameters(finding, source_root)
    ]
    sast = enrich_findings_with_ast(sast, {"routes": routes})
    findings = sort_findings(correlate_and_merge(sast, dast, routes))
    persisted_verifications = load_confirmed_results(target_id)
    if persisted_verifications:
        findings = [
            finding.model_copy(
                update={
                    "label": "Confirmed",
                    "url": verification.get("url") or finding.url,
                    "method": verification.get("method") or finding.method,
                    "parameter": verification.get("parameter") or finding.parameter,
                    "parameter_source": verification.get("parameter_source") or finding.parameter_source,
                    "evidence": verification.get("evidence"),
                    "http_status": verification.get("http_status"),
                    "confidence": 0.9,
                    "reason": "A bounded runtime probe produced vulnerability-specific response evidence.",
                    "routes": list(dict.fromkeys([*finding.routes, *([verification["route"]] if verification.get("route") else [])])),
                }
            )
            if finding.id in persisted_verifications and finding.source == "sast"
            else finding
            for finding in findings
        ]
        findings = sort_findings(findings)
    nodes, edges, route_ids = _route_nodes(target_id, routes)

    for finding in findings:
        matches = _finding_route_indices(finding, routes)
        node_type: NodeType = (
            "suppressed"
            if finding.source == "sast" and finding.reachable is False
            else "sink"
        )
        nodes.append(
            GraphNode(
                id=f"finding:{finding.id}",
                type=node_type,
                position={"x": 0.0, "y": 0.0},
                data=GraphNodeData(
                    label=f"{finding.cwe_id}: {finding.sink_type or finding.rule_id or 'finding'}",
                    target_id=target_id,
                    finding_id=finding.id,
                    finding_label=finding.label,
                    confidence=finding.confidence,
                    file=finding.file,
                    line=finding.line,
                    routes=finding.routes,
                    mapped_urls=[
                        f"{target_origin}{route}"
                        for route in finding.routes
                        if target_origin and route.startswith("/")
                    ],
                    cwe=finding.cwe_id,
                    evidence=finding.evidence,
                    evidence_items=finding.evidence_items,
                    payload=finding.payload,
                    risk_score=calculate_issue_risk_score(finding),
                    merged_from=finding.merged_from,
                    reason=finding.reason,
                    url=finding.url,
                    method=finding.method,
                    parameter=finding.parameter,
                    parameter_source=finding.parameter_source,
                    http_status=finding.http_status,
                    severity=finding.severity,
                    source=finding.source,
                    source_snippet=_source_excerpt(finding, source_root),
                    sink_type=finding.sink_type,
                    function=finding.function,
                    remediation=_REMEDIATION_BY_CWE.get(
                        finding.cwe_id,
                        "Validate the untrusted input at the application boundary, use the framework's safe API for this operation, and add a regression test for the reported case.",
                    ),
                ),
            )
        )
        for route_index in matches:
            _, controller_id = route_ids[route_index]
            edges.append(
                GraphEdge(
                    id=f"edge:{controller_id}:finding:{finding.id}",
                    source=controller_id,
                    target=f"finding:{finding.id}",
                    animated=finding.label == "Confirmed",
                )
            )
        if finding.evidence:
            evidence_id = f"evidence:{finding.id}"
            nodes.append(
                GraphNode(
                    id=evidence_id,
                    type="evidence",
                    position={"x": 0.0, "y": 0.0},
                    data=GraphNodeData(
                        label=finding.evidence[:160],
                        target_id=target_id,
                        finding_id=finding.id,
                        finding_label=finding.label,
                        evidence=finding.evidence,
                    ),
                )
            )
            edges.append(
                GraphEdge(
                    id=f"edge:finding:{finding.id}:{evidence_id}",
                    source=f"finding:{finding.id}",
                    target=evidence_id,
                    animated=finding.label == "Confirmed",
                )
            )

    labels = [finding.label for finding in findings]
    stats = GraphStats(
        target_id=target_id,
        total=len(findings),
        confirmed=labels.count("Confirmed"),
        corroborated=labels.count("Corroborated"),
        code_only=labels.count("Code only"),
        runtime_only=labels.count("Runtime only"),
        suppression_ratio=float(route_stats.get("suppression_ratio", 0.0)),
        cwe_types_covered=sorted(
            {finding.cwe_id for finding in findings if finding.cwe_id != "CWE-UNKNOWN"}
        ),
    )
    return GraphSnapshot(
        response=GraphResponse(
            target_id=target_id,
            nodes=_seed_node_positions(nodes),
            edges=edges,
            stats=stats,
        ),
        findings=tuple(findings),
    )


def get_graph_snapshot(target_id: TargetId) -> GraphSnapshot:
    now = time.monotonic()
    with _CACHE_LOCK:
        cached = _CACHE.get(target_id)
        if cached and now - cached[0] < _CACHE_TTL_SECONDS:
            return cached[1]

    snapshot = _build_snapshot(target_id)
    with _CACHE_LOCK:
        _CACHE[target_id] = (time.monotonic(), snapshot)
    return snapshot


def clear_graph_snapshot_cache(target_id: TargetId) -> None:
    """Force the next graph request to read reports written by a completed scan."""
    with _CACHE_LOCK:
        _CACHE.pop(target_id, None)
