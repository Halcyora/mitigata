from __future__ import annotations

import ast
import re
from pathlib import Path

from app.parsers.python_parser.ast_parser import PythonASTIndexer, PythonProjectIndex
from app.parsers.python_parser.flask_route_mapper import FlaskRouteMapper, RawFlaskRoute

from ..ast_mapper.route_schema import CodeScope, ParameterRead, RouteNode
from .base import TargetProfile


_PATH_PARAMETER = re.compile(r"<(?:[A-Za-z_][A-Za-z0-9_]*:)?([A-Za-z_][A-Za-z0-9_]*)>|\{([A-Za-z_][A-Za-z0-9_]*)(?:\:[^}]+)?\}")
_REQUEST_SOURCE = {
    "args": "query",
    "values": "query",
    "form": "form",
    "json": "json",
    "headers": "header",
    "query_params": "query", "path_params": "path", "GET": "query",
    "POST": "form", "FILES": "form", "COOKIES": "cookie",
}


class FlaskRouteAdapter:
    """Python web route discovery and enrichment for Flask, FastAPI and Django."""

    def __init__(self) -> None:
        self._profile_key: tuple[str, Path] | None = None
        self._index: PythonProjectIndex | None = None
        self._raw_routes: list[RawFlaskRoute] = []
        self._symbols: dict[tuple[str, str, str, str], ast.AST] = {}

    def _index_project(self, profile: TargetProfile) -> PythonProjectIndex:
        key = (profile.target_id, profile.source_dir.resolve())
        if self._profile_key != key or self._index is None:
            self._index = PythonASTIndexer().index_project(profile.source_dir)
            self._raw_routes = FlaskRouteMapper().extract_routes(self._index)
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
        self._index_project(profile)
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
                resolved=raw.resolved,
                unresolved_reasons=(
                    [raw.unresolved_reason]
                    if raw.unresolved_reason
                    else []
                ),
            )
            routes.append(route)
            self._symbols[self._route_key(route)] = raw.handler.node
        return routes

    def add_one_hop_scopes(
        self, routes: list[RouteNode], profile: TargetProfile
    ) -> None:
        index = self._index_project(profile)
        for route in routes:
            handler_node = self._symbols.get(self._route_key(route))
            if handler_node is None:
                route.resolved = False
                route.unresolved_reasons.append("handler AST was not indexed")
                continue
            calls = self._calls_in_function(handler_node)
            scopes = list(route.scopes)
            seen = {(scope.file, scope.function) for scope in scopes}
            current_file = scopes[0].file if scopes else ""
            for call in calls:
                resolved = index.resolve_imported_function(
                    current_file, self._call_name(call.func)
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
                (name, "path") for pair in _PATH_PARAMETER.findall(route.raw_url) for name in pair if name
            }
            for scope in route.scopes:
                context = index.files.get(scope.file)
                symbol = context.functions.get(scope.function) if context else None
                if symbol is None:
                    continue
                reads.update(self._request_reads(symbol.node))
                if scope == route.scopes[0] and isinstance(symbol.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    path_names = {name for pair in _PATH_PARAMETER.findall(route.raw_url) for name in pair if name}
                    for arg in symbol.node.args.args:
                        if arg.arg in {"self", "cls", "request", "req", "db", "session"} or arg.arg in path_names:
                            continue
                        annotation = ast.unparse(arg.annotation) if arg.annotation else ""
                        source = "body" if any(token in annotation for token in ("Body", "Form", "File", "UploadFile")) else "query"
                        reads.add((arg.arg, source))
            route.input_parameters = [
                ParameterRead(name=name, source=source)
                for name, source in sorted(reads)
            ]

    @staticmethod
    def _calls_in_function(node: ast.AST) -> list[ast.Call]:
        calls: list[ast.Call] = []

        class Visitor(ast.NodeVisitor):
            def visit_FunctionDef(self, child: ast.FunctionDef) -> None:
                if child is node:
                    for statement in child.body:
                        self.visit(statement)

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Lambda(self, child: ast.Lambda) -> None:
                return

            def visit_Call(self, child: ast.Call) -> None:
                calls.append(child)
                self.generic_visit(child)

        Visitor().visit(node)
        return calls

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = FlaskRouteAdapter._call_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    @staticmethod
    def _request_reads(node: ast.AST) -> set[tuple[str, str]]:
        reads: set[tuple[str, str]] = set()
        aliases: dict[str, str] = {}

        class Visitor(ast.NodeVisitor):
            def visit_FunctionDef(self, child: ast.FunctionDef) -> None:
                if child is node:
                    for statement in child.body:
                        self.visit(statement)

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Lambda(self, child: ast.Lambda) -> None:
                return

            def visit_Assign(self, child: ast.Assign) -> None:
                source = FlaskRouteAdapter._request_container(child.value, aliases)
                if source:
                    for target in child.targets:
                        if isinstance(target, ast.Name):
                            aliases[target.id] = source
                self.generic_visit(child)

            def visit_Call(self, child: ast.Call) -> None:
                if (
                    isinstance(child.func, ast.Attribute)
                    and child.func.attr in {"get", "getlist"}
                    and child.args
                    and isinstance(child.args[0], ast.Constant)
                    and isinstance(child.args[0].value, str)
                ):
                    source = FlaskRouteAdapter._request_container(
                        child.func.value, aliases
                    )
                    if source:
                        reads.add((child.args[0].value, source))
                self.generic_visit(child)

            def visit_Subscript(self, child: ast.Subscript) -> None:
                key = child.slice
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    source = FlaskRouteAdapter._request_container(
                        child.value, aliases
                    )
                    if source:
                        reads.add((key.value, source))
                self.generic_visit(child)

        Visitor().visit(node)
        return reads

    @staticmethod
    def _request_container(node: ast.AST, aliases: dict[str, str]) -> str | None:
        if isinstance(node, ast.Name):
            return aliases.get(node.id)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id in {"request", "req"}
                and node.func.attr == "get_json"
            ):
                return "json"
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in {"request", "req"}:
                return _REQUEST_SOURCE.get(node.attr)
        return None
