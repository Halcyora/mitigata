from __future__ import annotations

from ..ingestion.schema import UnifiedFinding
from .route_schema import RouteNode


def enrich_findings_with_ast(
    findings: list[UnifiedFinding],
    call_graph: dict[str, object],
) -> list[UnifiedFinding]:
    """Attach reachability only when a SAST location lies in a resolved route scope."""
    routes = call_graph.get("routes")
    if not isinstance(routes, list) or not all(
        isinstance(route, RouteNode) for route in routes
    ):
        raise ValueError("call_graph['routes'] must contain RouteNode values")

    enriched: list[UnifiedFinding] = []
    for finding in findings:
        if finding.source != "sast":
            enriched.append(finding)
            continue
        matching_routes = [
            route.normalized_url
            for route in routes
            if route.target_id == finding.target_id
            and route.resolved
            and route.contains_location(finding.file, finding.line)
        ]
        enriched.append(
            finding.model_copy(
                update={
                    "reachable": bool(matching_routes),
                    "routes": list(dict.fromkeys(matching_routes)),
                }
            )
        )
    return enriched
