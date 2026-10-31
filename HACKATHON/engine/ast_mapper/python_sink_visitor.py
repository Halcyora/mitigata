from __future__ import annotations

import ast
from pathlib import Path

from .route_schema import CodeScope
from .sink_detector import SINK_CWE_MAP, SinkFinding


_COMMANDS = {"system", "popen", "run", "call", "check_output", "check_call"}


def _function_nodes(tree: ast.Module):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _call_name(node.value)
        return f"{owner}.{node.attr}" if owner else node.attr
    return ""


def _dynamic(node: ast.AST) -> bool:
    return not isinstance(node, ast.Constant) or not isinstance(node.value, str)


def _classify(call: ast.Call) -> str | None:
    name = _call_name(call.func)
    short_name = name.rsplit(".", 1)[-1]
    if short_name == "execute" and call.args and _dynamic(call.args[0]):
        return "sql_injection"
    if short_name == "Markup":
        return "xss"
    if short_name == "render_template_string":
        return "ssti"
    if short_name in _COMMANDS and any(_dynamic(arg) for arg in call.args):
        return "command_injection"
    if short_name in {"eval", "exec"}:
        return "eval_injection"
    if short_name in {"loads", "load"} and name.startswith("pickle."):
        return "insecure_deserialisation"
    if short_name == "decode" and any(
        keyword.arg == "verify"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is False
        for keyword in call.keywords
    ):
        return "jwt_weak_secret"
    if short_name == "md5":
        return "weak_hash"
    if short_name in {"open", "resolve"} and call.args and _dynamic(call.args[0]):
        return "path_traversal"
    if short_name == "redirect" and call.args and _dynamic(call.args[0]):
        return "open_redirect"
    return None


def _scope_nodes(function: ast.AST) -> list[ast.AST]:
    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.nodes: list[ast.AST] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is function:
                self.nodes.append(node)
                for statement in node.body:
                    self.visit(statement)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def generic_visit(self, node: ast.AST) -> None:
            self.nodes.append(node)
            super().generic_visit(node)

    visitor = Visitor()
    visitor.visit(function)
    return visitor.nodes


def _hardcoded_secret_name(node: ast.AST) -> bool:
    try:
        target = ast.unparse(node).lower()
    except (AttributeError, ValueError):
        return False
    return any(
        marker in target
        for marker in ("secret", "password", "passwd", "credential", "api_key")
    )


def _html_interpolation(node: ast.Return) -> bool:
    if not isinstance(node.value, ast.JoinedStr):
        return False
    literal_text = "".join(
        part.value
        for part in node.value.values
        if isinstance(part, ast.Constant) and isinstance(part.value, str)
    )
    return "<" in literal_text and ">" in literal_text


def find_python_sinks(source_dir: str | Path, target_id: str) -> list[SinkFinding]:
    root = Path(source_dir).resolve()
    findings: list[SinkFinding] = []
    ignored = {".git", ".venv", "venv", "env", "__pycache__", "node_modules"}
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if any(part in ignored for part in relative.parts):
            continue
        source = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(source, filename=relative.as_posix())
        except SyntaxError as exc:
            raise ValueError(f"Unable to parse Python source {relative}: {exc}") from exc

        for function in _function_nodes(tree):
            start = min(
                [function.lineno, *(decorator.lineno for decorator in function.decorator_list)]
            )
            end = getattr(function, "end_lineno", function.lineno)
            scope = CodeScope(
                file=relative.as_posix(),
                start_line=start,
                end_line=end,
                function=function.name,
            )
            for node in _scope_nodes(function):
                sink_type: str | None = None
                if isinstance(node, ast.Call):
                    sink_type = _classify(node)
                elif isinstance(node, ast.Return) and _html_interpolation(node):
                    sink_type = "xss"
                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    target = (
                        node.targets[0]
                        if isinstance(node, ast.Assign)
                        else node.target
                    )
                    if (
                        _hardcoded_secret_name(target)
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)
                    ):
                        sink_type = "hardcoded_secret"
                if sink_type is None:
                    continue
                findings.append(
                    SinkFinding(
                        target_id=target_id,
                        cwe_id=SINK_CWE_MAP[sink_type],
                        sink_type=sink_type,
                        scope=scope,
                        line=getattr(node, "lineno", function.lineno),
                        evidence=(
                            _call_name(node.func)
                            if isinstance(node, ast.Call)
                            else sink_type
                        ),
                    )
                )
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            if (
                _hardcoded_secret_name(target)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                line = node.lineno
                findings.append(
                    SinkFinding(
                        target_id=target_id,
                        cwe_id=SINK_CWE_MAP["hardcoded_secret"],
                        sink_type="hardcoded_secret",
                        scope=CodeScope(
                            file=relative.as_posix(),
                            start_line=line,
                            end_line=line,
                            function="<module>",
                        ),
                        line=line,
                        evidence="hardcoded_secret",
                    )
                )
    return findings
