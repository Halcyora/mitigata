# app/parsers/python_parser/flask_route_mapper.py
import ast
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from app.normalizer.route_normalizer import join_url_paths, normalize_static_path
from app.parsers.python_parser.ast_parser import FunctionSymbol, PythonProjectIndex

HTTP_METHOD_SHORTHANDS = {"get", "post", "put", "delete", "patch", "options", "head"}
AUTH_DECORATOR_KEYWORDS = {"login_required", "jwt_required", "auth_required", "roles_required", "requires_auth"}


@dataclass
class RawFlaskRoute:
    raw_url: str
    normalized_url: str
    method: str
    handler: FunctionSymbol
    middlewares: List[str] = field(default_factory=list)
    resolved: bool = True
    unresolved_reason: Optional[str] = None


class FlaskRouteMapper:
    """Pass 2: Resolves Flask Blueprint prefixes and @route decorators into RawFlaskRoutes."""

    def extract_routes(self, index: PythonProjectIndex) -> List[RawFlaskRoute]:
        # Key: (rel_file_path, blueprint_var_name) -> declared prefix or unresolved.
        blueprint_defaults: Dict[Tuple[str, str], Optional[str]] = {}
        for rel_path, file_ctx in index.files.items():
            for node in ast.walk(file_ctx.tree):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    if self._is_call_named(node.value, "Blueprint") or self._is_call_named(node.value, "APIRouter"):
                        prefix = self._extract_kwarg_str(node.value, "url_prefix")
                        if prefix is None and any(
                            keyword.arg == "url_prefix" for keyword in node.value.keywords
                        ):
                            prefix = None
                        else:
                            prefix = prefix or ""
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                blueprint_defaults[(rel_path, target.id)] = prefix

        # A blueprint can be mounted at several prefixes; preserve each route.
        blueprint_prefixes: Dict[Tuple[str, str], List[Optional[str]]] = {}
        for rel_path, file_ctx in index.files.items():
            for node in ast.walk(file_ctx.tree):
                if (
                    isinstance(node, ast.Call)
                    and (self._is_method_named(node, "register_blueprint") or self._is_method_named(node, "include_router"))
                ):
                    if not node.args:
                        continue
                    bp_arg = node.args[0]
                    if not isinstance(bp_arg, ast.Name):
                        continue
                    local_key = (rel_path, bp_arg.id)
                    if bp_arg.id in file_ctx.imports:
                        target_mod, imported_name = file_ctx.imports[bp_arg.id]
                        target_file = index._resolve_module_path(target_mod)
                        blueprint_key = (
                            (target_file, imported_name) if target_file else local_key
                        )
                    else:
                        blueprint_key = local_key
                    if blueprint_key not in blueprint_defaults:
                        continue

                    default_prefix = blueprint_defaults[blueprint_key]
                    registration = self._extract_kwarg_str(node, "url_prefix")
                    dynamic_registration = registration is None and any(
                        keyword.arg == "url_prefix" for keyword in node.keywords
                    )
                    if dynamic_registration or default_prefix is None:
                        effective_prefix = None
                    else:
                        effective_prefix = join_url_paths(
                            registration or "", default_prefix or ""
                        )
                    blueprint_prefixes.setdefault(blueprint_key, []).append(
                        effective_prefix
                    )

        # Step 2C: Extract @app.route / @bp.route / @app.get / @bp.post decorated functions
        discovered_routes: List[RawFlaskRoute] = []
        for rel_path, file_ctx in index.files.items():
            for fn_name, fn_sym in file_ctx.functions.items():
                fn_node = fn_sym.node
                if not isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                middlewares = self._extract_middlewares(fn_node.decorator_list)

                for dec in fn_node.decorator_list:
                    route_info = self._parse_route_decorator(dec)
                    if not route_info:
                        continue
                    sub_path, methods, owner_name = route_info
                    blueprint_key = (rel_path, owner_name)
                    if blueprint_key in blueprint_defaults:
                        prefixes = blueprint_prefixes.get(blueprint_key, [])
                    else:
                        prefixes = [""]
                    for prefix in prefixes:
                        resolved = prefix is not None
                        full_raw_url = (
                            join_url_paths(prefix, sub_path)
                            if prefix is not None
                            else join_url_paths(sub_path)
                        )
                        norm_url = normalize_static_path(full_raw_url)
                        for method in methods:
                            discovered_routes.append(
                                RawFlaskRoute(
                                    raw_url=full_raw_url,
                                    normalized_url=norm_url,
                                    method=method.upper(),
                                    handler=fn_sym,
                                    middlewares=middlewares,
                                    resolved=resolved,
                                    unresolved_reason=(
                                        None
                                        if resolved
                                        else "blueprint mount prefix is dynamic or unresolved"
                                    ),
                                )
                            )

        # FastAPI and Django route declarations share the same normalized route model.
        discovered_routes.extend(self._extract_django_routes(index))
        unique = {}
        for route in discovered_routes:
            unique[(route.raw_url, route.method, route.handler.file, route.handler.name)] = route
        return list(unique.values())

    def _extract_django_routes(self, index: PythonProjectIndex) -> List[RawFlaskRoute]:
        """Extract Django path()/re_path() entries, including simple local include() trees."""
        output: List[RawFlaskRoute] = []
        route_names = {"path", "re_path"}
        for rel_path, ctx in index.files.items():
            functions = ctx.functions
            for node in ast.walk(ctx.tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id not in route_names:
                    continue
                if len(node.args) < 2 or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                    continue
                route_path = self._clean_django_path(node.args[0].value, node.func.id == "re_path")
                view = node.args[1]
                if isinstance(view, ast.Call) and isinstance(view.func, ast.Attribute) and view.func.attr == "as_view":
                    view = view.func.value
                if not isinstance(view, ast.Name) or view.id not in functions:
                    # A route may be declared in another module; use the indexed import table.
                    sym = index.resolve_imported_function(rel_path, self._expr_name(view))
                else:
                    sym = functions[view.id]
                if sym:
                    for method in self._django_methods(sym.node):
                        output.append(RawFlaskRoute(route_path, normalize_static_path(route_path), method, sym))

                # Expand include(module.urlpatterns) for modules represented in the project index.
                if isinstance(view, ast.Call) and self._is_call_named(view, "include") and view.args:
                    include_arg = view.args[0]
                    include_name = (
                        include_arg.value if isinstance(include_arg, ast.Constant) and isinstance(include_arg.value, str)
                        else self._expr_name(include_arg)
                    )
                    target_mod = include_name
                    if include_name in ctx.imports:
                        imported_mod, imported_name = ctx.imports[include_name]
                        target_mod = f"{imported_mod}.{imported_name}" if imported_name != "*" else imported_mod
                    target_file = index._resolve_module_path(target_mod)
                    if target_file and target_file in index.files:
                        for child in self._extract_django_routes_for_file(index, target_file):
                            joined = join_url_paths(route_path, child.raw_url)
                            output.append(RawFlaskRoute(joined, normalize_static_path(joined), child.method, child.handler))
        return output

    def _extract_django_routes_for_file(self, index: PythonProjectIndex, rel_path: str) -> List[RawFlaskRoute]:
        ctx = index.files[rel_path]
        output: List[RawFlaskRoute] = []
        for node in ast.walk(ctx.tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id not in {"path", "re_path"}:
                continue
            if len(node.args) < 2 or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                continue
            view = node.args[1]
            if isinstance(view, ast.Name) and view.id in ctx.functions:
                sym = ctx.functions[view.id]
            else:
                sym = index.resolve_imported_function(rel_path, self._expr_name(view))
            if sym:
                for method in self._django_methods(sym.node):
                    path = self._clean_django_path(node.args[0].value, node.func.id == "re_path")
                    output.append(RawFlaskRoute(path, normalize_static_path(path), method, sym))
        return output

    @staticmethod
    def _clean_django_path(path: str, regex: bool) -> str:
        if not regex:
            return path
        path = path.strip("^").rstrip("$")
        path = re.sub(r"\(\?P<([A-Za-z_]\w*)>[^)]+\)", r"{\1}", path)
        path = re.sub(r"\\d\+|\[\^?[^\]]+\]\+|\([^)]*\)", "{param}", path)
        return path

    @staticmethod
    def _expr_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute): return f"{FlaskRouteMapper._expr_name(node.value)}.{node.attr}"
        return ""

    @staticmethod
    def _django_methods(node: ast.AST) -> List[str]:
        methods = set()
        for child in ast.walk(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name in {"get", "post", "put", "patch", "delete", "head", "options"}:
                methods.add(child.name.upper())
        return sorted(methods) or ["GET", "POST"]

    def _parse_route_decorator(
        self,
        dec: ast.AST,
    ) -> Optional[Tuple[str, List[str], str]]:
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            return None

        attr_name = dec.func.attr
        owner_name = dec.func.value.id if isinstance(dec.func.value, ast.Name) else ""

        if attr_name not in {"route", "api_route"} and attr_name not in HTTP_METHOD_SHORTHANDS:
            return None

        # Extract route path string from first positional argument or 'rule' kwarg
        sub_path = None
        if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
            sub_path = dec.args[0].value
        else:
            sub_path = self._extract_kwarg_str(dec, "rule")

        if sub_path is None:
            return None

        # Determine HTTP methods
        if attr_name in HTTP_METHOD_SHORTHANDS:
            methods = [attr_name.upper()]
        else:
            methods = self._extract_methods_kwarg(dec) or ["GET"]

        return sub_path, methods, owner_name

    @staticmethod
    def _extract_middlewares(decorators: List[ast.AST]) -> List[str]:
        middlewares: List[str] = []
        for dec in decorators:
            name = ""
            if isinstance(dec, ast.Name):
                name = dec.id
            elif isinstance(dec, ast.Attribute):
                name = dec.attr
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    name = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    name = dec.func.attr
            if name and (name in AUTH_DECORATOR_KEYWORDS or "auth" in name.lower() or "login" in name.lower()):
                middlewares.append(name)
        return middlewares

    @staticmethod
    def _is_call_named(call_node: ast.Call, target_name: str) -> bool:
        if isinstance(call_node.func, ast.Name):
            return call_node.func.id == target_name
        if isinstance(call_node.func, ast.Attribute):
            return call_node.func.attr == target_name
        return False

    @staticmethod
    def _is_method_named(call_node: ast.Call, method_name: str) -> bool:
        return isinstance(call_node.func, ast.Attribute) and call_node.func.attr == method_name

    @staticmethod
    def _extract_kwarg_str(call_node: ast.Call, kw_name: str) -> Optional[str]:
        for kw in call_node.keywords:
            if kw.arg == kw_name and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
        return None

    @staticmethod
    def _extract_methods_kwarg(call_node: ast.Call) -> Optional[List[str]]:
        for kw in call_node.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                methods = [
                    elt.value.upper()
                    for elt in kw.value.elts
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                ]
                return methods if methods else None
        return None
