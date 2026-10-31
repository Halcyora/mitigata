from __future__ import annotations

from engine.ast_mapper.route_schema import CodeScope, ParameterRead, RouteNode
from engine.dast_planner.planner import build_scan_plan
from engine.ingestion.schema import UnifiedFinding


def _route(
    path: str,
    handler: str,
    line: int,
    *,
    helper: tuple[str, int, int] | None = None,
    parameters: list[ParameterRead] | None = None,
) -> RouteNode:
    scopes = [
        CodeScope(
            file="app/routes.py",
            start_line=line,
            end_line=line + 10,
            function=handler,
        )
    ]
    if helper:
        scopes.append(
            CodeScope(
                file=helper[0],
                start_line=helper[1],
                end_line=helper[2],
                function="shared_helper",
            )
        )
    return RouteNode(
        target_id="flask_demo",
        raw_url=path,
        normalized_url=path,
        methods=["GET"],
        handler=handler,
        scopes=scopes,
        input_parameters=parameters or [],
    )


def _finding(file: str, line: int, cwe: str = "CWE-89") -> UnifiedFinding:
    return UnifiedFinding(
        id=f"finding-{line}",
        target_id="flask_demo",
        source="sast",
        cwe_id=cwe,
        file=file,
        line=line,
        severity="HIGH",
    )


def test_plan_prioritizes_exact_scope_and_preserves_a_broad_fallback():
    vulnerable = _route(
        "/orders/<int:order_id>",
        "get_order",
        10,
        parameters=[
            ParameterRead(name="order_id", source="path"),
            ParameterRead(name="q", source="query"),
        ],
    )
    unrelated = _route("/health", "health", 40)

    plan = build_scan_plan(
        "flask_demo",
        "http://target-flask:5050",
        [_finding("app/routes.py", 14)],
        [vulnerable, unrelated],
    )

    assert len(plan.targeted_tasks) == 1
    task = plan.targeted_tasks[0]
    assert task.phase == "TARGETED"
    assert task.priority_score < 100
    assert task.reason_codes == [
        "SAST_CWE_MATCH",
        "ROUTE_SCOPE_MATCH",
        "PARAMETER_SURFACE_MATCH",
    ]
    assert task.zap_rule_ids == ["40018"]
    assert task.parameters == [
        {"name": "order_id", "source": "path"},
        {"name": "q", "source": "query"},
    ]
    assert len({task.route_id for task in plan.broad_tasks}) == 2
    assert plan.targeted_tasks[0].route_id in {
        task.route_id for task in plan.broad_tasks
    }
    targeted_route_broad_task = next(
        broad_task
        for broad_task in plan.broad_tasks
        if broad_task.route_id == plan.targeted_tasks[0].route_id
    )
    assert targeted_route_broad_task.excluded_zap_rule_ids == ["40018"]


def test_plan_prioritizes_helper_scope_and_marks_shared_helper_ambiguous():
    first = _route(
        "/first",
        "first",
        10,
        helper=("app/shared.py", 30, 40),
        parameters=[ParameterRead(name="q", source="query")],
    )
    second = _route(
        "/second",
        "second",
        50,
        helper=("app/shared.py", 30, 40),
        parameters=[ParameterRead(name="q", source="query")],
    )
    finding = _finding("app/shared.py", 35)

    plan = build_scan_plan(
        "flask_demo", "http://target-flask:5050", [finding], [first, second]
    )

    assert len(plan.targeted_tasks) == 2
    assert all(task.priority_score >= 300 for task in plan.targeted_tasks)
    assert all("MULTIPLE_ROUTE_CANDIDATES" in task.reason_codes for task in plan.targeted_tasks)


def test_plan_recognizes_exact_scope_even_if_handler_scope_is_not_first_scope():
    route = _route(
        "/profile",
        "render_profile",
        30,
        helper=("app/routes.py", 80, 95),
        parameters=[ParameterRead(name="user_id", source="path")],
    )
    route.scopes = [
        CodeScope(file="app/helpers.py", start_line=90, end_line=98, function="shared_helper"),
        CodeScope(file="app/routes.py", start_line=30, end_line=40, function="render_profile"),
    ]
    finding = _finding("app/routes.py", 35)

    plan = build_scan_plan(
        "flask_demo", "http://target-flask:5050", [finding], [route]
    )

    assert len(plan.targeted_tasks) == 1
    assert plan.targeted_tasks[0].priority_score < 100
    assert "ROUTE_SCOPE_MATCH" in plan.targeted_tasks[0].reason_codes


def test_plan_uses_lower_priority_for_incomplete_input_and_unknown_rules():
    no_inputs = _route("/item", "get_item", 10)
    unknown_rule = _finding("app/routes.py", 11, "CWE-999")

    plan = build_scan_plan(
        "flask_demo", "http://target-flask:5050", [unknown_rule], [no_inputs]
    )

    assert plan.targeted_tasks == []
    assert len(plan.broad_tasks) == 1
    assert plan.broad_tasks[0].phase == "BROAD"
    assert plan.unresolved_finding_ids == []


def test_plan_rejects_cross_target_evidence():
    route = _route("/item", "get_item", 10)
    other_target = _finding("app/routes.py", 11).model_copy(
        update={"target_id": "juice_shop"}
    )

    try:
        build_scan_plan(
            "flask_demo", "http://target-flask:5050", [other_target], [route]
        )
    except ValueError as exc:
        assert "different target_id" in str(exc)
    else:
        raise AssertionError("cross-target finding should not be accepted")
