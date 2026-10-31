from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from scripts import zap_api_driver


def test_task_url_substitutes_route_parameters_within_selected_origin():
    assert zap_api_driver._task_url(
        "http://target-flask:5050", "/orders/<int:order_id>"
    ) == "http://target-flask:5050/orders/1"
    assert zap_api_driver._task_url(
        "http://target-juice-shop:3000", "/api/orders/:order_id"
    ) == "http://target-juice-shop:3000/api/orders/1"


@pytest.mark.parametrize(
    "path",
    [
        "http://example.com/escape",
        "//example.com/escape",
        "/../../outside",
        "/safe\\..\\outside",
        "/safe?next=http://example.com",
    ],
)
def test_task_url_rejects_non_route_paths(path: str):
    with pytest.raises(ValueError, match="invalid route path"):
        zap_api_driver._task_url("http://target-flask:5050", path)


def test_request_data_binds_only_supported_query_and_form_inputs():
    get_url, get_method, get_body = zap_api_driver._request_data(
        {
            "url": "http://target-flask:5050/orders/1",
            "method": "GET",
            "parameters": [
                {"name": "search", "source": "query"},
                {"name": "body", "source": "json"},
            ],
        }
    )
    assert get_url.endswith("?search=mitigata_scan")
    assert get_method == "GET"
    assert get_body is None

    post_url, post_method, post_body = zap_api_driver._request_data(
        {
            "url": "http://target-flask:5050/orders",
            "method": "POST",
            "parameters": [
                {"name": "page", "source": "query"},
                {"name": "name", "source": "form"},
                {"name": "body", "source": "json"},
            ],
        }
    )
    assert post_url.endswith("?page=mitigata_scan")
    assert post_method == "POST"
    assert post_body == "name=mitigata_scan"


def test_scan_progress_handles_zap_plugin_status_shape():
    assert zap_api_driver._scan_progress_complete(
        {
            "scanProgress": [
                "http://target-flask:5050",
                {
                    "HostProcess": [
                        {
                            "Plugin": [
                                "Path Traversal",
                                "6",
                                "release",
                                "Complete",
                                "12",
                                "0",
                                "0",
                            ]
                        }
                    ]
                },
            ]
        }
    )
    assert not zap_api_driver._scan_progress_complete({"scanProgress": []})
    assert not zap_api_driver._scan_progress_complete(
        {"scanProgress": [{"Plugin": ["SQL Injection", "40018", "release", "Running"]}]}
    )


def test_execute_runs_targeted_tasks_before_broad_and_limits_context(monkeypatch):
    calls = []

    class FakeZapClient:
        def __init__(self, api_key):
            assert api_key == "unit-test-key"

        def wait_ready(self):
            calls.append(("ready",))

        def request(self, component, operation, name, **params):
            calls.append((component, operation, name, params))
            if (component, operation, name) == ("context", "action", "newContext"):
                return {"contextId": "1"}
            if (component, operation, name) == ("ascan", "view", "scanners"):
                return {
                    "scanners": [
                        {
                            "id": "40018",
                            "allDependenciesAvailable": "true",
                        }
                    ]
                }
            if (component, operation, name) == ("ascan", "action", "scan"):
                return {
                    "scan": str(
                        sum(
                            len(call) > 2 and call[2] == "scan"
                            for call in calls
                        )
                    )
                }
            if (component, operation, name) == ("ascan", "view", "scanProgress"):
                return {"scanProgress": "100"}
            if (component, operation, name) == ("spider", "action", "scan"):
                return {"scan": "0"}
            if (component, operation, name) == ("spider", "view", "status"):
                return {"status": "100"}
            if (component, operation, name) == ("alert", "view", "alerts"):
                return {"alerts": []}
            return {"Result": "OK"}

    monkeypatch.setattr(zap_api_driver, "ZapClient", FakeZapClient)
    deadline = datetime.now(timezone.utc) + timedelta(minutes=2)
    targeted = {
        "task_id": "targeted",
        "target_id": "flask_demo",
        "route_id": "route-1",
        "raw_url": "/orders",
        "normalized_url": "/orders",
        "method": "GET",
        "phase": "TARGETED",
        "zap_rule_ids": ["40018"],
        "excluded_zap_rule_ids": [],
        "parameters": [{"name": "q", "source": "query"}],
        "status": "QUEUED",
    }
    broad = {
        "task_id": "broad",
        "target_id": "flask_demo",
        "route_id": "route-1",
        "raw_url": "/orders",
        "normalized_url": "/orders",
        "method": "GET",
        "phase": "BROAD",
        "zap_rule_ids": [],
        "excluded_zap_rule_ids": ["40018"],
        "parameters": [],
        "status": "QUEUED",
    }
    plan = {
        "scan_id": "scan-1",
        "target_id": "flask_demo",
        "target_url": "http://target-flask:5050",
        "deadline_at": deadline.isoformat(),
        "targeted_tasks": [targeted],
        "broad_tasks": [broad],
    }

    report = zap_api_driver.execute({"api_key": "unit-test-key", "plan": plan})

    assert report["scan_status"] == "COMPLETED"
    assert [task["status"] for task in report["tasks"]] == [
        "COMPLETED",
        "COMPLETED",
    ]
    assert report["coverage"] == {
        "targeted_completed": 1,
        "targeted_total": 1,
        "broad_completed": 1,
        "broad_total": 1,
        "cutoff": False,
    }
    context_includes = [
        call for call in calls if call[:3] == ("context", "action", "includeInContext")
    ]
    assert context_includes[0][3]["regex"] == r"^http://target\-flask:5050(?:/.*)?$"
    access_urls = [
        call for call in calls if call[:3] == ("core", "action", "accessUrl")
    ]
    assert access_urls[0][3] == {
        "url": "http://target-flask:5050/orders?q=mitigata_scan",
        "followRedirects": "false",
    }
    spiders = [call for call in calls if call[:3] == ("spider", "action", "scan")]
    scans = [call for call in calls if call[:3] == ("ascan", "action", "scan")]
    assert spiders[0][3]["url"].endswith("?q=mitigata_scan")
    assert spiders[0][3]["contextName"].startswith("mitigata-")
    assert spiders[0][3]["subtreeOnly"] == "true"
    assert scans[0][3]["url"].endswith("?q=mitigata_scan")
    assert scans[0][3]["contextId"] == "1"
    assert scans[1][3]["contextId"] == "1"
