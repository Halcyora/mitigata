from __future__ import annotations

from fastapi.testclient import TestClient

from engine.api import main as api_main
from engine.api.graph import (
    GraphResponse,
    GraphSnapshot,
    GraphStats,
    _build_snapshot,
    _stable_findings,
)
from engine.ast_mapper.route_schema import CodeScope, ParameterRead, RouteNode
from engine.ingestion.schema import UnifiedFinding


def test_graph_snapshot_correlates_and_counts_target_findings(monkeypatch):
    route = RouteNode(
        target_id="flask_demo",
        raw_url="/users/<int:user_id>",
        normalized_url="/users/{user_id}",
        methods=["GET"],
        handler="get_user",
        scopes=[
            CodeScope(
                file="app.py",
                start_line=10,
                end_line=20,
                function="get_user",
            )
        ],
        input_parameters=[ParameterRead(name="search", source="query")],
    )
    sast = UnifiedFinding(
        id="random-sast-id",
        target_id="flask_demo",
        source="sast",
        cwe_id="CWE-89",
        label="Code only",
        file="app.py",
        line=14,
        sink_type="sql_injection",
        confidence=0.7,
    )
    dast = UnifiedFinding(
        id="random-dast-id",
        target_id="flask_demo",
        source="dast",
        cwe_id="CWE-89",
        url="http://target-flask:5050/users/4",
        method="GET",
        parameter="search",
        parameter_source="query",
        evidence="Database error in response",
        label="Runtime only",
    )
    monkeypatch.setattr(
        "engine.api.graph._profile_data",
        lambda target_id: {
            "target_id": target_id,
            "language": "python",
            "framework": "flask",
            "source_dir": "unused",
        },
    )
    monkeypatch.setattr(
        "engine.api.graph._routes_and_stats",
        lambda target_id, profile: (
            [route],
            {"suppression_ratio": 0.25},
        ),
    )
    monkeypatch.setattr(
        "engine.api.graph._load_findings", lambda target_id: ([sast], [dast])
    )

    snapshot = _build_snapshot("flask_demo")

    assert snapshot.response.target_id == "flask_demo"
    assert snapshot.response.stats.total == 1
    assert snapshot.response.stats.confirmed == 1
    assert snapshot.response.stats.code_only == 0
    assert snapshot.response.stats.runtime_only == 0
    assert snapshot.response.stats.suppression_ratio == 0.25
    assert snapshot.response.stats.cwe_types_covered == ["CWE-89"]
    finding = snapshot.findings[0]
    assert finding.label == "Confirmed"
    assert finding.id == "random-sast-id"
    finding_node = next(
        node for node in snapshot.response.nodes if node.data.finding_id == finding.id
    )
    assert finding_node.type == "sink"
    assert finding_node.position["y"] == 360.0
    assert finding_node.data.finding_label == "Confirmed"
    assert finding_node.data.evidence == "Database error in response"
    assert any(edge.animated for edge in snapshot.response.edges)


def test_finding_ids_are_stable_and_target_scoped():
    finding = UnifiedFinding(
        target_id="flask_demo",
        source="sast",
        cwe_id="CWE-89",
        file="app.py",
        line=14,
        rule_id="sql-injection",
    )
    first = _stable_findings([finding], "flask_demo")[0]
    same_finding = _stable_findings(
        [finding.model_copy(update={"id": "new-parser-generated-id"})],
        "flask_demo",
    )[0]
    other_target = _stable_findings([finding], "juice_shop")[0]

    assert first.id == same_finding.id
    assert first.id != other_target.id


def test_graph_and_verification_stream_are_target_scoped(monkeypatch):
    finding = UnifiedFinding(
        id="stable-finding-id",
        target_id="flask_demo",
        source="sast",
        cwe_id="CWE-89",
        label="Code only",
        file="app.py",
        line=14,
        url="/users/{user_id}",
        method="GET",
        parameter="user_id",
        parameter_source="path",
        sink_type="sql_injection",
    )
    response = GraphResponse(
        target_id="flask_demo",
        nodes=[],
        edges=[],
        stats=GraphStats(
            target_id="flask_demo",
            total=1,
            confirmed=0,
            code_only=1,
            runtime_only=0,
            suppression_ratio=0.0,
            cwe_types_covered=["CWE-89"],
        ),
    )
    snapshot = GraphSnapshot(response=response, findings=(finding,))
    other_target = GraphSnapshot(
        response=GraphResponse(
            target_id="juice_shop",
            nodes=[],
            edges=[],
            stats=GraphStats(
                target_id="juice_shop",
                total=0,
                confirmed=0,
                code_only=0,
                runtime_only=0,
                suppression_ratio=0.0,
                cwe_types_covered=[],
            ),
        ),
        findings=(),
    )
    monkeypatch.setattr(
        api_main,
        "get_graph_snapshot",
        lambda target_id: snapshot if target_id == "flask_demo" else other_target,
    )

    monkeypatch.setattr(
        api_main,
        "_verification_candidates",
        lambda candidate, _target: [(candidate, "/users/{user_id}")],
    )

    async def fake_verification_states(initial_state):
        yield {
            **initial_state,
            "label": "Code only",
            "probe_history": [{"variant": 0, "status": 200}],
        }
        yield {
            **initial_state,
            "label": "Confirmed",
            "evidence": "Runtime evidence",
            "probe_history": [
                {"variant": 0, "status": 200},
                {"variant": 1, "status": 200},
            ],
        }

    monkeypatch.setattr(
        api_main, "iter_verification_states", fake_verification_states
    )
    client = TestClient(api_main.app)

    graph_response = client.get("/api/graph", params={"target_id": "flask_demo"})
    assert graph_response.status_code == 200
    assert graph_response.json()["stats"]["target_id"] == "flask_demo"

    stream_response = client.get(
        "/api/verify/stable-finding-id/stream",
        params={"target_id": "flask_demo"},
    )
    assert stream_response.status_code == 200
    assert stream_response.headers["content-type"].startswith("text/event-stream")
    assert '"label":"Confirmed"' in stream_response.text
    assert '"probe_history":[{"variant":0,"status":200},{"variant":1,"status":200}]' in stream_response.text
    assert '"done":true' in stream_response.text

    missing_finding = client.get(
        "/api/verify/stable-finding-id/stream",
        params={"target_id": "juice_shop"},
    )
    assert missing_finding.status_code == 404
