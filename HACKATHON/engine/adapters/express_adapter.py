from __future__ import annotations

import re
from pathlib import Path

from app.parsers.javascript_parser.express_route_mapper import (
    ExpressRouteMapper,
    RawExpressRoute,
)
from app.parsers.javascript_parser.ts_ast_parser import (
    TSFunctionSymbol,
    TSProjectIndex,
    TypeScriptASTIndexer,
)

from ..ast_mapper.route_schema import CodeScope, ParameterRead, RouteNode
from .base import TargetProfile


_PATH_PARAMETER = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")


class ExpressRouteAdapter:
    """Express route discovery and source enrichment through the TS Compiler API."""

    def __init__(self) -> None:
        self._profile_key: tuple[str, Path] | None = None
        self._index: TSProjectIndex | None = None
        self._raw_routes: list[RawExpressRoute] = []
        self._symbols: dict[tuple[str, str, str, str], TSFunctionSymbol] = {}

    def _index_project(self, profile: TargetProfile) -> TSProjectIndex:
        key = (profile.target_id, profile.source_dir.resolve())
        if self._profile_key != key or self._index is None:
            self._index = TypeScriptASTIndexer().index_project(profile.source_dir)
            self._raw_routes = ExpressRouteMapper().extract_routes(self._index)
            self._symbols.clear()
            self._profile_key = key
        return self._index

    @staticmethod
    def _route_key(route: RouteNode) -> tuple[str, str, str, str]:
        return (
            route.raw_url,
            ",".join(route.methods),
            route.handler,
            route.scopes[0].file if route.scopes else "",
        )

    def discover_routes(self, profile: TargetProfile) -> list[RouteNode]:
        index = self._index_project(profile)
        routes: list[RouteNode] = []
        for raw in self._raw_routes:
            route = RouteNode(
                target_id=profile.target_id,
                raw_url=raw.raw_url,
                normalized_url=raw.normalized_url,
                methods=[raw.method],
                handler=raw.handler.name,
                scopes=[
                    CodeScope(
                        file=raw.handler.file,
                        start_line=raw.handler.start_line,
                        end_line=raw.handler.end_line,
                        function=raw.handler.name,
                    )
                ],
                resolved=raw.resolved
                and not self._handler_is_unresolved(raw, index),
                unresolved_reasons=[
                    reason
                    for reason in (
                        raw.unresolved_reason,
                        (
                            "handler import or export could not be resolved"
                            if self._handler_is_unresolved(raw, index)
                            else None
                        ),
                    )
                    if reason
                ],
            )
            routes.append(route)
            self._symbols[self._route_key(route)] = raw.handler
        return routes

    @staticmethod
    def _handler_is_unresolved(
        raw: RawExpressRoute, index: TSProjectIndex
    ) -> bool:
        if raw.handler.name.startswith("inline_"):
            return False
        context = index.files.get(raw.handler.file)
        if context is None:
            return True
        return raw.handler.name not in context.functions

    def add_one_hop_scopes(
        self, routes: list[RouteNode], profile: TargetProfile
    ) -> None:
        index = self._index_project(profile)
        for route in routes:
            handler = self._symbols.get(self._route_key(route))
            if handler is None:
                route.resolved = False
                route.unresolved_reasons.append("handler AST was not indexed")
                continue
            scopes = list(route.scopes)
            seen = {(scope.file, scope.function) for scope in scopes}
            for call in handler.calls:
                resolved = index.resolve_handler_symbol(
                    handler.file, call.get("callee", "")
                )
                if resolved is None or (resolved.file, resolved.name) in seen:
                    continue
                scopes.append(
                    CodeScope(
                        file=resolved.file,
                        start_line=resolved.start_line,
                        end_line=resolved.end_line,
                        function=resolved.name,
                    )
                )
                seen.add((resolved.file, resolved.name))
            route.scopes = scopes

    def extract_request_parameters(
        self, routes: list[RouteNode], profile: TargetProfile
    ) -> None:
        index = self._index_project(profile)
        for route in routes:
            reads: set[tuple[str, str]] = {
                (name, "path") for name in _PATH_PARAMETER.findall(route.raw_url)
            }
            for scope in route.scopes:
                context = index.files.get(scope.file)
                symbol = context.functions.get(scope.function) if context else None
                if symbol is None and scope.file == route.scopes[0].file:
                    symbol = self._symbols.get(self._route_key(route))
                if symbol is None:
                    continue
                for parameter in symbol.params:
                    source = parameter.get("source")
                    name = parameter.get("name")
                    if source == "body":
                        source = "json"
                    if source in {"path", "query", "form", "json", "header"} and name:
                        reads.add((str(name), source))
            route.input_parameters = [
                ParameterRead(name=name, source=source)
                for name, source in sorted(reads)
            ]
