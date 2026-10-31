from __future__ import annotations

from engine.ast_mapper.route_schema import CodeScope, ParameterRead, RouteNode
from engine.ingestion.incremental import IncrementalCorrelator, correlate_incremental
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


def test_incremental_correlator_confirms_match_and_records_events():
    route = _route()
    sast = UnifiedFinding(
        id="sast-1",
        target_id="flask_demo",
        source="sast",
        cwe_id="CWE-89",
        file="routes/orders.py",
        line=18,
    )
    dast = UnifiedFinding(
        id="dast-1",
        target_id="flask_demo",
        source="dast",
        cwe_id="CWE-89",
        url="http://target-flask:5050/orders/42?q=sql",
        method="GET",
        parameter="q",
        parameter_source="query",
        evidence="SQL error",
    )

    correlator = IncrementalCorrelator([sast], [route], scan_id="scan-1")
    status, confirmed = correlator.ingest_alert(dast)

    assert status == "confirmed"
    assert confirmed is not None
    assert confirmed.label == "Confirmed"
    assert any(event.kind == "CONFIRMED" for event in correlator.events)

    finalized = correlator.finalize()
    assert [finding.label for finding in finalized] == ["Confirmed"]


def test_incremental_correlator_deduplicates_and_keeps_runtime_only_when_unmatched():
    route = _route()
    sast = UnifiedFinding(
        id="sast-1",
        target_id="flask_demo",
        source="sast",
        cwe_id="CWE-89",
        file="routes/orders.py",
        line=18,
    )
    duplicate = UnifiedFinding(
        id="dast-1",
        target_id="flask_demo",
        source="dast",
        cwe_id="CWE-89",
        url="http://target-flask:5050/orders/42?q=sql",
        method="GET",
        parameter="q",
        parameter_source="query",
        evidence="SQL error",
    )
    unmatched = UnifiedFinding(
        id="dast-2",
        target_id="flask_demo",
        source="dast",
        cwe_id="CWE-89",
        url="http://target-flask:5050/orders/99?q=oops",
        method="GET",
        parameter="q",
        parameter_source="query",
        evidence="No match",
    )

    results = correlate_incremental([sast], [duplicate, duplicate, unmatched], [route], scan_id="scan-2")
    labels = [finding.label for finding in results]
    assert labels.count("Confirmed") == 1
    assert labels.count("Runtime only") == 1
    assert labels.count("Code only") == 0
