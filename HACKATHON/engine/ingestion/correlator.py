from __future__ import annotations

from urllib.parse import urlparse

from ..ast_mapper.route_schema import RouteNode
from .schema import UnifiedFinding


def correlate_and_merge(
    sast: list[UnifiedFinding],
    dast: list[UnifiedFinding],
    routes: list[RouteNode],
) -> list[UnifiedFinding]:
    """Merge only pairs with matching target, CWE, route, scope, and input evidence."""
    merged: list[UnifiedFinding] = []
    consumed_dast_ids: set[str] = set()

    for sast_finding in sast:
        match: tuple[RouteNode, UnifiedFinding] | None = None
        for dast_finding in dast:
            if dast_finding.id in consumed_dast_ids:
                continue
            if dast_finding.target_id != sast_finding.target_id:
                continue
            if dast_finding.cwe_id != sast_finding.cwe_id or not dast_finding.url:
                continue

            path = urlparse(dast_finding.url).path
            if not path:
                continue

            for route in routes:
                if route.target_id != sast_finding.target_id:
                    continue
                if not route.matches_path(path):
                    continue
                if not dast_finding.method or not route.matches_method(dast_finding.method):
                    continue
                if not route.contains_location(sast_finding.file, sast_finding.line):
                    continue
                if (
                    not dast_finding.parameter
                    or not dast_finding.parameter_source
                ):
                    continue
                if not any(
                    read.name == dast_finding.parameter
                    and read.source == dast_finding.parameter_source
                    for read in route.input_parameters
                ):
                    continue
                match = (route, dast_finding)
                break
            if match is not None:
                break

        if match is None:
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
            continue

        route, dast_finding = match
        consumed_dast_ids.add(dast_finding.id)
        merged.append(
            sast_finding.model_copy(
                update={
                    "label": "Confirmed",
                    "url": dast_finding.url,
                    "method": dast_finding.method,
                    "parameter": dast_finding.parameter,
                    "parameter_source": dast_finding.parameter_source,
                    "evidence": dast_finding.evidence,
                    "http_status": dast_finding.http_status,
                    "merged_from": [sast_finding.id, dast_finding.id],
                    "reason": "Matched target, CWE, normalized route, code scope, and request parameter/source.",
                    "confidence": 0.95,
                    "routes": [route.normalized_url],
                }
            )
        )

    for dast_finding in dast:
        if dast_finding.id not in consumed_dast_ids:
            merged.append(dast_finding.model_copy(update={"label": "Runtime only"}))

    label_rank = {"Confirmed": 0, "Code only": 1, "Runtime only": 2}
    merged.sort(key=lambda finding: label_rank.get(finding.label or "Code only", 1))
    return merged
