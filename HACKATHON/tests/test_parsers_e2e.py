# tests/test_parsers_e2e.py
from pathlib import Path
from app.parsers.base_parser import get_parser
from app.normalizer.route_normalizer import match_dast_to_route
from app.schemas.route import NormalizedRoute


def test_flask_three_pass_parser(tmp_path: Path):
    # 1. Create multi-file Flask fixture
    (tmp_path / "routes").mkdir()
    (tmp_path / "utils").mkdir()

    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "from routes.orders import orders_bp\n"
        "app = Flask(__name__)\n"
        "app.register_blueprint(orders_bp, url_prefix='/api/orders')\n",
        encoding="utf-8",
    )

    (tmp_path / "routes" / "orders.py").write_text(
        "from flask import Blueprint, request\n"
        "from utils.db import fetch_order_by_filter\n"
        "orders_bp = Blueprint('orders', __name__)\n\n"
        "@orders_bp.route('/<int:order_id>', methods=['GET'])\n"
        "def get_order(order_id):\n"
        "    search_filter = request.args.get('q')\n"
        "    return fetch_order_by_filter(order_id, search_filter)\n",
        encoding="utf-8",
    )

    (tmp_path / "utils" / "db.py").write_text(
        "def fetch_order_by_filter(order_id, query_str):\n"
        "    sql = f'SELECT * FROM orders WHERE id={order_id} AND q={query_str}'\n"
        "    return sql\n",
        encoding="utf-8",
    )

    parser = get_parser("python")
    routes = parser.parse_project(tmp_path)

    assert len(routes) == 1
    route = routes[0]
    assert route.raw_url == "/api/orders/<int:order_id>"
    assert route.normalized_url == "/api/orders/{param}"
    assert route.method == "GET"
    assert route.file == "routes/orders.py"
    assert {p.name for p in route.parameters} == {"order_id", "q"}
    assert len(route.callees) == 1
    assert route.callees[0].function_name == "fetch_order_by_filter"
    assert route.callees[0].file == "utils/db.py"
    assert route.callees[0].start_line == 1

    # Verify DAST runtime URL matching
    matched = match_dast_to_route("http://localhost:5000/api/orders/42?q=test", "GET", routes)
    assert matched is not None
    assert matched.handler_function == "get_order"

    mixed_slug_routes = [
        NormalizedRoute(
            raw_url="/users/<int:user_id>",
            normalized_url="/users/{param}",
            method="GET",
            handler_function="show_user",
            file="app.py",
            start_line=1,
            end_line=3,
            parameters=[],
            callees=[],
        )
    ]
    slug_match = match_dast_to_route("http://localhost:5000/users/guest42?tab=profile", "GET", mixed_slug_routes)
    assert slug_match is not None
    assert slug_match.handler_function == "show_user"
