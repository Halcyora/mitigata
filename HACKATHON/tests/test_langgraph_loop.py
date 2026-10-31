from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest

import engine.langgraph_loop.nodes as verification_nodes
from engine.ingestion.schema import UnifiedFinding
from engine.langgraph_loop.graph import verify_finding
from engine.langgraph_loop.nodes import (
    build_local_probe_url,
    probe_generator,
    response_evaluator,
    runtime_executor,
    should_retry,
)
from engine.langgraph_loop.profile import load_target_profile
from engine.langgraph_loop.state import new_alert_state, state_from_finding


def _state(**overrides: str) -> dict[str, Any]:
    values: dict[str, Any] = {
        "finding_id": "finding-1",
        "target_id": "flask_demo",
        "route": "https://attacker.example/api/items/{param}?existing=1",
        "method": "GET",
        "parameter": "id",
        "parameter_source": "path",
        "sink_type": "sql_injection",
    }
    state = new_alert_state(**values)
    state.update(overrides)
    return state


def _write_profile(directory: Path, target_url: str = "http://target-flask:5050") -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "flask_demo.yaml").write_text(
        "target_id: flask_demo\n"
        f"target_url: {target_url}\n",
        encoding="utf-8",
    )


def test_state_requires_complete_metadata_and_only_sast_finding():
    state = _state()
    assert state["label"] == "Code only"
    assert state["probe_variant"] == 0
    assert state["probe_history"] == []

    finding = UnifiedFinding(
        id="runtime",
        target_id="flask_demo",
        source="dast",
        cwe_id="CWE-89",
    )
    with pytest.raises(ValueError, match="Only SAST"):
        state_from_finding(finding)

    confirmed_finding = UnifiedFinding(
        target_id="flask_demo",
        source="sast",
        cwe_id="CWE-89",
        label="Confirmed",
    )
    with pytest.raises(ValueError, match="Only unverified"):
        state_from_finding(confirmed_finding)


def test_profile_loader_rejects_external_targets(tmp_path: Path, monkeypatch):
    _write_profile(tmp_path, "https://example.com")
    monkeypatch.setenv("MITIGATA_CONFIG_DIR", str(tmp_path))

    with pytest.raises(ValueError, match="loopback or internal"):
        load_target_profile("flask_demo")


def test_probe_url_rebuilds_origin_and_safely_materializes_route():
    url = build_local_probe_url(
        "http://target-flask:5050",
        "https://attacker.example/api/items/{param}?existing=1",
        "id",
        "path",
        "canary value",
    )

    assert url == (
        "http://target-flask:5050/api/items/canary%20value?existing=1"
    )


@pytest.mark.parametrize(
    "route",
    [
        "/api/../admin",
        "/api/%2e%2e/admin",
        "/api/%2f%2fevil.example/",
        r"/api\admin",
    ],
)
def test_probe_url_rejects_path_traversal_and_ambiguous_paths(route: str):
    with pytest.raises(ValueError, match="invalid_route"):
        build_local_probe_url(
            "http://target-flask:5050",
            route,
            "q",
            "query",
            "canary",
        )


class _FakeResponse:
    def __init__(self, status_code: int, body: str, delay: float = 0):
        self.status_code = status_code
        self._body = body.encode()
        self._delay = delay

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def aiter_bytes(self):
        if self._delay:
            await asyncio.sleep(self._delay)
        yield self._body


class _FakeClient:
    def __init__(self, bodies: list[str], calls: list[dict[str, Any]], **kwargs: Any):
        self._bodies = bodies
        self._calls = calls
        self._kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    @asynccontextmanager
    async def stream(self, method: str, url: str, **kwargs: Any):
        self._calls.append(
            {"method": method, "url": url, "request": kwargs, "client": self._kwargs}
        )
        yield _FakeResponse(
            200,
            self._bodies.pop(0),
            delay=self._kwargs.get("response_delay", 0),
        )


def test_graph_retries_once_then_confirms_and_records_history(
    tmp_path: Path, monkeypatch
):
    _write_profile(tmp_path)
    monkeypatch.setenv("MITIGATA_CONFIG_DIR", str(tmp_path))
    calls: list[dict[str, Any]] = []
    bodies = ["no signal", "sqlite3 OperationalError"]

    def fake_client(*, timeout, follow_redirects, trust_env):
        return _FakeClient(
            bodies,
            calls,
            timeout=timeout,
            follow_redirects=follow_redirects,
            trust_env=trust_env,
        )

    monkeypatch.setattr("engine.langgraph_loop.nodes.httpx.AsyncClient", fake_client)
    finding = UnifiedFinding(
        id="sast-1",
        target_id="flask_demo",
        source="sast",
        cwe_id="CWE-89",
        sink_type="sql_injection",
        url="https://attacker.example/api/items/{param}?existing=1",
        method="GET",
        parameter="id",
        parameter_source="path",
    )

    result = asyncio.run(verify_finding(finding))

    assert result["label"] == "Confirmed"
    assert "sqlite3" in (result["evidence"] or "")
    assert len(result["probe_history"]) == 2
    assert [entry["variant"] for entry in result["probe_history"]] == [0, 1]
    assert all(call["url"].startswith("http://target-flask:5050/") for call in calls)
    assert all(call["client"]["timeout"].read == 2.0 for call in calls)
    assert all(call["client"]["follow_redirects"] is False for call in calls)
    assert all(call["client"]["trust_env"] is False for call in calls)


def test_graph_ends_unverified_without_retrying_unsafe_method(monkeypatch):
    state = _state(method="DELETE")
    generated = probe_generator(state)
    assert should_retry(
        {
            **generated,
            "error": "unsafe_http_method",
            "label": "UNVERIFIED",
        }
    ) == "end"


def test_runtime_executor_enforces_overall_deadline(
    tmp_path: Path, monkeypatch
):
    _write_profile(tmp_path)
    monkeypatch.setenv("MITIGATA_CONFIG_DIR", str(tmp_path))
    calls: list[dict[str, Any]] = []

    def fake_client(*, timeout, follow_redirects, trust_env):
        return _FakeClient(
            ["slow response"],
            calls,
            timeout=timeout,
            follow_redirects=follow_redirects,
            trust_env=trust_env,
            response_delay=0.05,
        )

    real_timeout = asyncio.timeout
    requested_deadlines: list[float] = []

    def shortened_deadline(seconds: float):
        requested_deadlines.append(seconds)
        return real_timeout(0.01)

    monkeypatch.setattr(
        "engine.langgraph_loop.nodes.httpx.AsyncClient", fake_client
    )
    monkeypatch.setattr(verification_nodes.asyncio, "timeout", shortened_deadline)

    result = asyncio.run(runtime_executor(probe_generator(_state())))

    assert requested_deadlines == [2.0]
    assert result["error"] == "probe_timeout"
    assert result["probe_history"][0]["error"] == "probe_timeout"


def test_evaluator_does_not_confirm_unrendered_template_or_unrelated_math():
    ssti = _state(sink_type="ssti", probe_payload="{{7*7}}", http_response="{{7*7}}")
    assert response_evaluator(ssti)["label"] == "Code only"

    evaluation = _state(sink_type="eval_injection", probe_payload="1+1")
    assert response_evaluator(
        {**evaluation, "http_response": "The number 2 appears in this page"}
    )["label"] == "Code only"


def test_unsupported_sink_is_explicitly_unverified():
    state = probe_generator(_state(sink_type="unknown"))
    assert state["label"] == "UNVERIFIED"
    assert state["error"] == "unsupported_sink_type"

    hardcoded_secret = probe_generator(_state(sink_type="hardcoded_secret"))
    assert hardcoded_secret["label"] == "UNVERIFIED"
    assert hardcoded_secret["error"] == "no_safe_runtime_probe_available"
