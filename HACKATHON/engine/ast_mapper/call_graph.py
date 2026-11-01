from __future__ import annotations

from ..adapters.base import TargetProfile
from ..adapters.express_adapter import ExpressRouteAdapter
from ..adapters.flask_adapter import FlaskRouteAdapter
from ..adapters.base import RouteAdapter
from .javascript_sink_visitor import find_javascript_sinks
from .python_sink_visitor import find_python_sinks
from .sink_detector import SinkFinding, summarize_route_and_sink_coverage


def adapter_for(profile: TargetProfile) -> RouteAdapter:
    language = profile.language.lower()
    framework = profile.framework.lower()
    if language == "python" and framework in {"flask", "fastapi", "django"}:
        return FlaskRouteAdapter()
    if language in {"javascript", "typescript", "js", "ts"} and framework == "express":
        return ExpressRouteAdapter()
    raise ValueError(
        f"Unsupported route adapter: language={profile.language!r}, "
        f"framework={profile.framework!r}"
    )


def build_call_graph(profile: TargetProfile) -> dict[str, object]:
    adapter = adapter_for(profile)
    routes = adapter.discover_routes(profile)
    adapter.add_one_hop_scopes(routes, profile)
    adapter.extract_request_parameters(routes, profile)
    if profile.language.lower() == "python":
        sinks: list[SinkFinding] = find_python_sinks(
            profile.source_dir, profile.target_id
        )
    else:
        sinks = find_javascript_sinks(profile.source_dir, profile.target_id)
    stats = summarize_route_and_sink_coverage(routes, sinks, profile.target_id)
    return {"routes": routes, "sinks": sinks, "stats": stats}
