from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.ast_mapper.route_schema import CodeScope, ParameterRead, RouteNode
from engine.ingestion.correlator import correlate_and_merge
from engine.ingestion.schema import UnifiedFinding
from engine.ingestion.semgrep_parser import normalize_finding_path, parse_semgrep_json
from engine.ingestion.zap_parser import parse_zap_json


def test_unified_finding_defaults_and_bounds():
    finding = UnifiedFinding(
        target_id="flask_demo",
        source="sast",
        cwe_id="CWE-89",
    )

    assert finding.label is None
    assert finding.severity == "MEDIUM"
    assert finding.routes == []
    assert finding.merged_from == []
    with pytest.raises(ValueError):
        UnifiedFinding(
            target_id="flask_demo",
            source="sast",
            cwe_id="CWE-89",
            confidence=1.1,
        )


def test_code_scope_rejects_host_paths_and_invalid_spans():
    with pytest.raises(ValueError, match="target-relative"):
        CodeScope(
            file="C:\\source\\app.py",
            start_line=1,
            end_line=3,
            function="handler",
        )
    with pytest.raises(ValueError, match="end_line"):
        CodeScope(
            file="app.py",
            start_line=5,
            end_line=3,
            function="handler",
        )


def test_semgrep_parser_extracts_metadata_and_fallback_cwes(tmp_path: Path):
    report = tmp_path / "semgrep.json"
    report.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "custom.rule",
                        "path": "app\\routes.py",
                        "start": {"line": 12},
                        "extra": {
                            "severity": "ERROR",
                            "metadata": {"cwe": ["CWE-89: SQL injection"]},
                        },
                    },
                    {
                        "check_id": "python.lang.security.audit.eval-detected",
                        "path": "app/unsafe.py",
                        "start": {"line": 4},
                        "extra": {"metadata": {}},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = parse_semgrep_json(report, "flask_demo")

    assert [finding.cwe_id for finding in findings] == ["CWE-89", "CWE-95"]
    assert findings[0].file == "app/routes.py"
    assert findings[0].sink_type == "sql_injection"
    assert findings[0].severity == "ERROR"
    assert findings[0].label == "Code only"
    assert findings[1].sink_type == "eval_injection"


def test_normalize_finding_path_strips_source_root(tmp_path: Path):
    source_root = tmp_path / "source"
    finding_path = source_root / "app" / "main.py"

    normalized = normalize_finding_path(
        str(finding_path),
        "flask_demo",
        source_root=source_root,
    )

    assert normalized == "app/main.py"
    assert (
        normalize_finding_path(
            "/targets/vulnerable_flask/source/app/app.py",
            "flask_demo",
        )
        == "app/app.py"
    )
    with pytest.raises(ValueError, match="escapes"):
        normalize_finding_path("../outside.py", "flask_demo")


def test_zap_parser_supports_site_format_and_normalizes_alert_fields(tmp_path: Path):
    report = tmp_path / "zap.json"
    report.write_text(
        json.dumps(
            {
                "alerts": [],
                "site": [
                    {
                        "alerts": [
                            {
                                "cweid": "89",
                                "riskdesc": "High (Medium)",
                                "url": "http://localhost/api/orders/42",
                                "method": "POST",
                                "param": "order_id",
                                "paramType": "URL_PATH",
                                "evidence": "x" * 600,
                                "pluginId": "40018",
                                "statusCode": 500,
                            },
                            {"cweid": "0", "riskdesc": "Informational"},
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = parse_zap_json(report, "flask_demo")

    assert len(findings) == 2
    assert findings[0].cwe_id == "CWE-89"
    assert findings[0].sink_type == "sql_injection"
    assert findings[0].parameter_source == "path"
    assert findings[0].severity == "HIGH"
    assert len(findings[0].evidence or "") == 500
    assert findings[0].rule_id == "40018"
    assert findings[0].http_status == 500
    assert findings[1].cwe_id == "CWE-UNKNOWN"
    assert findings[1].severity == "INFO"


def test_correlator_requires_all_evidence_and_merges_confirmed_pair():
    route = RouteNode(
        target_id="flask_demo",
        raw_url="/api/orders/<int:order_id>",
        normalized_url="/api/orders/{param}",
        methods=["GET"],
        handler="orders.get_order",
        scopes=[
            CodeScope(
                file="routes/orders.py",
                start_line=10,
                end_line=30,
                function="get_order",
            )
        ],
        input_parameters=[ParameterRead(name="q", source="query")],
    )
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
        url="http://localhost/api/orders/42?q=x",
        method="GET",
        parameter="q",
        parameter_source="query",
        evidence="SQL error",
    )

    merged = correlate_and_merge([sast], [dast], [route])

    assert len(merged) == 1
    assert merged[0].label == "Confirmed"
    assert merged[0].merged_from == ["sast-1", "dast-1"]
    assert merged[0].routes == ["/api/orders/{param}"]
    assert merged[0].confidence == 0.95
    assert merged[0].evidence == "SQL error"


@pytest.mark.parametrize(
    ("dast_overrides", "route_overrides", "expected_sast_reachable"),
    [
        ({"method": "POST"}, {}, True),
        ({"parameter": "id"}, {}, True),
        ({"parameter_source": "form"}, {}, True),
        ({"target_id": "other_target"}, {}, True),
        ({"cwe_id": "CWE-79"}, {}, True),
        ({}, {"scopes": []}, False),
        ({}, {"normalized_url": "/api/users/{param}"}, True),
    ],
)
def test_correlator_does_not_confirm_partial_matches(
    dast_overrides: dict[str, object],
    route_overrides: dict[str, object],
    expected_sast_reachable: bool,
):
    route_data: dict[str, object] = {
        "target_id": "flask_demo",
        "raw_url": "/api/orders/<int:id>",
        "normalized_url": "/api/orders/{param}",
        "methods": ["GET"],
        "handler": "orders.get_order",
        "scopes": [
            CodeScope(
                file="routes/orders.py",
                start_line=10,
                end_line=30,
                function="get_order",
            )
        ],
        "input_parameters": [ParameterRead(name="q", source="query")],
    }
    route_data.update(route_overrides)
    route = RouteNode(**route_data)
    sast = UnifiedFinding(
        id="sast-1",
        target_id="flask_demo",
        source="sast",
        cwe_id="CWE-89",
        file="routes/orders.py",
        line=18,
    )
    dast_data: dict[str, object] = {
        "id": "dast-1",
        "target_id": "flask_demo",
        "source": "dast",
        "cwe_id": "CWE-89",
        "url": "http://localhost/api/orders/42?q=x",
        "method": "GET",
        "parameter": "q",
        "parameter_source": "query",
    }
    dast_data.update(dast_overrides)
    dast = UnifiedFinding(**dast_data)

    merged = correlate_and_merge([sast], [dast], [route])

    assert [finding.label for finding in merged] == ["Code only", "Runtime only"]
    assert merged[0].reachable is expected_sast_reachable
