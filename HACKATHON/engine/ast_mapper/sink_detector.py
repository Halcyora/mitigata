from __future__ import annotations

from pydantic import BaseModel, Field

from .route_schema import CodeScope


class SinkFinding(BaseModel):
    target_id: str
    cwe_id: str
    sink_type: str
    scope: CodeScope
    line: int = Field(ge=1)
    evidence: str


SINK_CWE_MAP: dict[str, str] = {
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "command_injection": "CWE-78",
    "eval_injection": "CWE-95",
    "insecure_deserialisation": "CWE-502",
    "ssti": "CWE-94",
    "jwt_weak_secret": "CWE-347",
    "weak_hash": "CWE-916",
    "hardcoded_secret": "CWE-798",
    "path_traversal": "CWE-22",
    "open_redirect": "CWE-601",
}


def summarize_route_and_sink_coverage(
    routes: list[object], sinks: list[SinkFinding], target_id: str
) -> dict[str, int | float]:
    target_routes = [route for route in routes if route.target_id == target_id]
    target_sinks = [sink for sink in sinks if sink.target_id == target_id]
    reachable = sum(
        any(
            route.resolved and route.contains_location(sink.scope.file, sink.line)
            for route in target_routes
        )
        for sink in target_sinks
    )
    total = len(target_sinks)
    return {
        "route_count": len(target_routes),
        "sink_count": total,
        "reachable_sink_count": reachable,
        "suppressed_sink_count": total - reachable,
        "suppression_ratio": (total - reachable) / total if total else 0.0,
    }
