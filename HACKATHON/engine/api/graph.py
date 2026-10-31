from __future__ import annotations

import hashlib
import json
import logging
import os
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
from ..ingestion.correlator import correlate_and_merge
from ..ingestion.schema import UnifiedFinding
from ..ingestion.semgrep_parser import parse_semgrep_json
from ..ingestion.zap_parser import parse_zap_json

logger = logging.getLogger(__name__)

TargetId = Literal["flask_demo", "juice_shop"]
NodeType = Literal["endpoint", "controller", "sink", "evidence", "suppressed"]
FindingLabel = Literal["Confirmed", "Code only", "Runtime only"]
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
    cwe: str | None = None
    evidence: str | None = None


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
    if not finding.url:
        return []
    path = urlparse(finding.url).path
    return [
        index
        for index, route in enumerate(routes)
        if route.matches_path(path) and route.matches_method(finding.method)
    ]


def _build_snapshot(target_id: TargetId) -> GraphSnapshot:
    profile = _profile_data(target_id)
    routes, route_stats = _routes_and_stats(target_id, profile)
    sast, dast = _load_findings(target_id)
    sast = enrich_findings_with_ast(sast, {"routes": routes})
    findings = sort_findings(correlate_and_merge(sast, dast, routes))
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
                    label=f"{finding.cwe_id} · {finding.sink_type or finding.rule_id or 'finding'}",
                    target_id=target_id,
                    finding_id=finding.id,
                    finding_label=finding.label,
                    confidence=finding.confidence,
                    file=finding.file,
                    line=finding.line,
                    cwe=finding.cwe_id,
                    evidence=finding.evidence,
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
            nodes=nodes,
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
