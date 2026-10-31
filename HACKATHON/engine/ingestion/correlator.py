from __future__ import annotations

from typing import Literal
from urllib.parse import urlparse

from ..ast_mapper.route_schema import RouteNode
from .deduplication import deduplicate_findings
from .schema import UnifiedFinding

CorrelationLevel = Literal["Confirmed", "Corroborated"]


def candidate_match_level(
    route: RouteNode,
    sast_finding: UnifiedFinding,
    dast_finding: UnifiedFinding,
) -> CorrelationLevel | None:
    """Classify a route-level SAST/DAST match by its input evidence strength."""
    if (
        route.target_id != sast_finding.target_id
        or route.target_id != dast_finding.target_id
        or dast_finding.cwe_id != sast_finding.cwe_id
        or not dast_finding.url
        or not dast_finding.method
        or not route.resolved
    ):
        return None

    path = urlparse(dast_finding.url).path
    if (
        not path
        or not route.matches_path(path)
        or not route.matches_method(dast_finding.method)
        or not route.contains_location(sast_finding.file, sast_finding.line)
    ):
        return None

    # A complete, matching parameter/source pair is the strongest evidence.
    inputs = route.input_parameters
    parameter = dast_finding.parameter
    parameter_source = dast_finding.parameter_source
    if not inputs:
        return "Corroborated"
    if parameter and parameter_source:
        return (
            "Confirmed"
            if any(
                read.name == parameter and read.source == parameter_source
                for read in inputs
            )
            else None
        )
    if parameter and not any(read.name == parameter for read in inputs):
        return None
    if parameter_source and not any(
        read.source == parameter_source for read in inputs
    ):
        return None
    return "Corroborated"


def _merge_pair(
    sast_finding: UnifiedFinding,
    dast_finding: UnifiedFinding,
    route: RouteNode,
    level: CorrelationLevel,
) -> UnifiedFinding:
    confirmed = level == "Confirmed"
    return sast_finding.model_copy(
        update={
            "label": level,
            "url": dast_finding.url,
            "method": dast_finding.method,
            "parameter": dast_finding.parameter,
            "parameter_source": dast_finding.parameter_source,
            "evidence": dast_finding.evidence,
            "http_status": dast_finding.http_status,
            "merged_from": list(
                dict.fromkeys(
                    [
                        *sast_finding.merged_from,
                        sast_finding.id,
                        *dast_finding.merged_from,
                        dast_finding.id,
                    ]
                )
            ),
            "reason": (
                "Matched target, CWE, route, method, code scope, and request "
                "parameter/source."
                if confirmed
                else "Matched target, CWE, route, method, and code scope; "
                "request input evidence is incomplete or unavailable."
            ),
            "confidence": 0.95 if confirmed else 0.72,
            "routes": list(dict.fromkeys([*dast_finding.routes, route.normalized_url])),
        }
    )


def correlate_and_merge(
    sast: list[UnifiedFinding],
    dast: list[UnifiedFinding],
    routes: list[RouteNode],
) -> list[UnifiedFinding]:
    """Correlate exact input matches and retain weaker route-level evidence."""
    sast = deduplicate_findings(sast, routes)
    dast = deduplicate_findings(dast, routes)
    consumed_dast_ids: set[str] = set()
    merged_by_sast_id: dict[str, UnifiedFinding] = {}

    # Resolve all high-confidence pairs before allowing weaker pairs to consume
    # an alert that might exactly match a later SAST finding.
    for level in ("Confirmed", "Corroborated"):
        for sast_finding in sast:
            if sast_finding.id in merged_by_sast_id:
                continue
            match: tuple[RouteNode, UnifiedFinding] | None = None
            for dast_finding in dast:
                if dast_finding.id in consumed_dast_ids:
                    continue
                for route in routes:
                    if candidate_match_level(route, sast_finding, dast_finding) == level:
                        match = (route, dast_finding)
                        break
                if match is not None:
                    break
            if match is None:
                continue
            route, dast_finding = match
            consumed_dast_ids.add(dast_finding.id)
            merged_by_sast_id[sast_finding.id] = _merge_pair(
                sast_finding, dast_finding, route, level
            )

    merged: list[UnifiedFinding] = []
    for sast_finding in sast:
        correlated = merged_by_sast_id.get(sast_finding.id)
        if correlated is not None:
            merged.append(correlated)
            continue
        merged.append(
            sast_finding.model_copy(
                update={
                    "label": "Code only",
                    "reachable": any(
                        route.target_id == sast_finding.target_id
                        and route.resolved
                        and route.contains_location(sast_finding.file, sast_finding.line)
                        for route in routes
                    ),
                }
            )
        )

    for dast_finding in dast:
        if dast_finding.id not in consumed_dast_ids:
            merged.append(dast_finding.model_copy(update={"label": "Runtime only"}))

    label_rank = {
        "Confirmed": 0,
        "Corroborated": 1,
        "Code only": 2,
        "Runtime only": 3,
    }
    merged.sort(key=lambda finding: label_rank.get(finding.label or "Code only", 2))
    return merged
