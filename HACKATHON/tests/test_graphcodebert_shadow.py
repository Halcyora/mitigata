from __future__ import annotations

from engine.ast_mapper.route_schema import CodeScope, ParameterRead, RouteNode
from engine.code_intelligence.shadow_ranker import GraphCodeBERTShadowRanker
from engine.dast_planner.planner import build_scan_plan
from engine.ingestion.schema import UnifiedFinding


def _route() -> RouteNode:
    return RouteNode(
        target_id="flask_demo",
        raw_url="/orders/<int:order_id>",
        normalized_url="/orders/{order_id}",
        methods=["GET"],
        handler="orders.get_order",
        scopes=[
            CodeScope(
                file="routes/orders.py",
                start_line=10,
                end_line=35,
                function="get_order",
            )
        ],
        input_parameters=[ParameterRead(name="q", source="query")],
    )


def _finding() -> UnifiedFinding:
    return UnifiedFinding(
        id="sast-1",
        target_id="flask_demo",
        source="sast",
        cwe_id="CWE-89",
        file="routes/orders.py",
        line=18,
        severity="HIGH",
    )


def test_shadow_ranker_falls_back_to_skipped_when_model_not_available(monkeypatch):
    monkeypatch.setattr(
        GraphCodeBERTShadowRanker,
        "is_available",
        property(lambda self: False),
    )

    router = _route()
    finding = _finding()
    assessment = GraphCodeBERTShadowRanker(mode="SHADOW").build_assessment("scan-1", finding, router)

    assert assessment.status == "SKIPPED"
    assert assessment.score_calibration == "UN_CALIBRATED"
    assert "TRANSFORMERS_UNAVAILABLE" in assessment.limitations


def test_build_scan_plan_keeps_shadow_mode_advisory_and_non_blocking():
    route = _route()
    plan = build_scan_plan(
        "flask_demo",
        "http://target-flask:5050",
        [_finding()],
        [route],
        model_mode="SHADOW",
    )

    assert plan.code_intelligence["mode"] == "SHADOW"
    assert plan.code_intelligence["status"] == "SKIPPED"
    assert len(plan.intelligence_assessments) == 1
    assert plan.intelligence_assessments[0]["status"] == "SKIPPED"
    assert plan.targeted_tasks[0].priority_score < 100
