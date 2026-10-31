from __future__ import annotations

from pathlib import Path

from engine.adapters.base import TargetProfile
from engine.ast_mapper.call_graph import build_call_graph
from engine.ast_mapper.merger import enrich_findings_with_ast
from engine.ingestion.correlator import correlate_and_merge
from engine.ingestion.schema import UnifiedFinding


def test_flask_route_maps_blueprint_helper_and_request_inputs(tmp_path: Path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "utils").mkdir()
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "from routes.orders import orders_bp\n"
        "app = Flask(__name__)\n"
        "app.register_blueprint(orders_bp, url_prefix='/api')\n",
        encoding="utf-8",
    )
    (tmp_path / "routes" / "orders.py").write_text(
        "from flask import Blueprint, request\n"
        "from utils.db import fetch_order\n"
        "orders_bp = Blueprint('orders', __name__)\n"
        "@orders_bp.route('/orders/<int:id>', methods=['GET'])\n"
        "def get_order(id):\n"
        "    query = request.args.get('q')\n"
        "    return fetch_order(id, query)\n",
        encoding="utf-8",
    )
    (tmp_path / "utils" / "db.py").write_text(
        "def fetch_order(order_id, query):\n"
        "    return f'{order_id}:{query}'\n",
        encoding="utf-8",
    )

    graph = build_call_graph(
        TargetProfile("flask_demo", "python", "flask", tmp_path)
    )
    route = graph["routes"][0]

    assert route.raw_url == "/api/orders/<int:id>"
    assert route.normalized_url == "/api/orders/{param}"
    assert route.methods == ["GET"]
    assert ("id", "path") in {
        (read.name, read.source) for read in route.input_parameters
    }
    assert ("q", "query") in {
        (read.name, read.source) for read in route.input_parameters
    }
    assert any(scope.file == "utils/db.py" for scope in route.scopes)


def test_express_route_maps_mount_imported_callee_and_inputs(tmp_path: Path):
    routes_dir = tmp_path / "routes"
    routes_dir.mkdir()
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const ordersRouter = express.Router();\n"
        "const orders = require('./routes/orders');\n"
        "ordersRouter.get('/orders/:id', orders.getOrder);\n"
        "app.use('/api', ordersRouter);\n",
        encoding="utf-8",
    )
    (routes_dir / "orders.js").write_text(
        "const lookup = require('./lookup');\n"
        "function getOrder(req, res) {\n"
        "  const id = req.params.id;\n"
        "  const q = req.query.q;\n"
        "  return lookup.findOrder(id, q);\n"
        "}\n"
        "module.exports = { getOrder };\n",
        encoding="utf-8",
    )
    (routes_dir / "lookup.js").write_text(
        "function findOrder(id, q) { return `${id}:${q}`; }\n"
        "module.exports = { findOrder };\n",
        encoding="utf-8",
    )

    graph = build_call_graph(
        TargetProfile("juice_shop", "javascript", "express", tmp_path)
    )
    route = next(route for route in graph["routes"] if route.normalized_url)

    assert route.raw_url == "/api/orders/:id"
    assert route.normalized_url == "/api/orders/{param}"
    assert route.methods == ["GET"]
    assert {("id", "path"), ("q", "query")} <= {
        (read.name, read.source) for read in route.input_parameters
    }
    assert any(scope.file == "routes/lookup.js" for scope in route.scopes)


def test_static_multiple_mounts_are_preserved_and_dynamic_mount_is_unresolved(
    tmp_path: Path,
):
    (tmp_path / "routes.py").write_text(
        "from flask import Blueprint\n"
        "bp = Blueprint('bp', __name__)\n"
        "@bp.get('/users/<int:id>')\n"
        "def get_user(id): return id\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "from routes import bp\n"
        "app = Flask(__name__)\n"
        "app.register_blueprint(bp, url_prefix='/api')\n"
        "app.register_blueprint(bp, url_prefix='/v2')\n",
        encoding="utf-8",
    )

    graph = build_call_graph(
        TargetProfile("flask_demo", "python", "flask", tmp_path)
    )
    assert {
        route.normalized_url for route in graph["routes"]
    } == {"/api/users/{param}", "/v2/users/{param}"}


def test_dynamic_express_mount_never_becomes_a_strict_route_match(tmp_path: Path):
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const router = express.Router();\n"
        "router.get('/users/:id', (req, res) => res.send(req.params.id));\n"
        "app.use(getPrefix(), router);\n",
        encoding="utf-8",
    )

    graph = build_call_graph(
        TargetProfile("juice_shop", "javascript", "express", tmp_path)
    )
    assert len(graph["routes"]) == 1
    route = graph["routes"][0]
    assert route.resolved is False
    assert route.unresolved_reasons
    assert route.matches_path("/users/12") is False


def test_reachability_and_correlation_require_exact_target_route_scope_and_input():
    from engine.ast_mapper.route_schema import CodeScope, ParameterRead, RouteNode

    route = RouteNode(
        target_id="flask_demo",
        raw_url="/api/orders/<int:id>",
        normalized_url="/api/orders/{param}",
        methods=["GET"],
        handler="get_order",
        scopes=[
            CodeScope(
                file="routes/orders.py",
                start_line=10,
                end_line=20,
                function="get_order",
            )
        ],
        input_parameters=[ParameterRead(name="q", source="query")],
    )
    sast = UnifiedFinding(
        id="sast",
        target_id="flask_demo",
        source="sast",
        cwe_id="CWE-89",
        file="routes/orders.py",
        line=15,
    )
    good_dast = UnifiedFinding(
        id="dast-good",
        target_id="flask_demo",
        source="dast",
        cwe_id="CWE-89",
        url="http://localhost/api/orders/42?q=x",
        method="GET",
        parameter="q",
        parameter_source="query",
    )
    wrong_target = good_dast.model_copy(
        update={"id": "dast-other-target", "target_id": "juice_shop"}
    )
    wrong_parameter = good_dast.model_copy(
        update={"id": "dast-wrong-param", "parameter": "other"}
    )
    missing_method = good_dast.model_copy(
        update={"id": "dast-missing-method", "method": None}
    )

    merged = correlate_and_merge(
        [sast], [wrong_target, wrong_parameter, missing_method, good_dast], [route]
    )
    assert merged[0].label == "Confirmed"
    assert merged[0].merged_from == ["sast", "dast-good"]
    assert [finding.label for finding in merged[1:]] == [
        "Runtime only",
        "Runtime only",
        "Runtime only",
    ]

    enriched = enrich_findings_with_ast(
        [sast],
        {
            "routes": [route],
        },
    )
    assert enriched[0].reachable is True
    unrelated = sast.model_copy(update={"file": "unrelated.py"})
    assert enrich_findings_with_ast([unrelated], {"routes": [route]})[0].reachable is False
