#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

API_ROOT = "http://127.0.0.1:8090"
API_WAIT_SECONDS = 60
API_TIMEOUT_SECONDS = 10
TASK_TIMEOUT_SECONDS = 30
TARGETED_TASK_TIMEOUT_SECONDS = 15
BROAD_TASK_TIMEOUT_SECONDS = 15
POLL_INTERVAL_SECONDS = 2
FINALIZATION_RESERVE_SECONDS = 15
BROAD_SCANNER_IDS = {"6", "90020", "40012", "40014", "40018", "20019"}
_FLASK_PATH_PARAMETER = re.compile(r"<(?:[A-Za-z_][A-Za-z0-9_]*:)?([A-Za-z_][A-Za-z0-9_]*)>")
_EXPRESS_PATH_PARAMETER = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")

TARGET_ORIGINS = {
    "flask_demo": ("target-flask", 5050),
    "juice_shop": ("target-juice-shop", 3000),
}


class ZapApiError(RuntimeError):
    pass


class ZapDeadlineError(ZapApiError):
    pass


class ZapClient:
    def __init__(self, api_key: str, deadline: float | None = None) -> None:
        self.api_key = api_key
        self.deadline = deadline or (time.monotonic() + API_WAIT_SECONDS + 300)

    def request(self, component: str, operation: str, name: str, **params: str) -> dict[str, Any]:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ZapDeadlineError("DAST budget exhausted")
        query = urlencode({"apikey": self.api_key, **params})
        url = f"{API_ROOT}/JSON/{component}/{operation}/{name}/?{query}"
        request = Request(url, headers={"Accept": "application/json"})
        try:
            with urlopen(request, timeout=min(API_TIMEOUT_SECONDS, remaining)) as response:
                payload = json.load(response)
        except (HTTPError, URLError, TimeoutError) as exc:
            if time.monotonic() >= self.deadline:
                raise ZapDeadlineError("DAST budget exhausted during a ZAP API call") from exc
            detail = exc.read().decode("utf-8", errors="replace") if isinstance(exc, HTTPError) else str(exc)
            raise ZapApiError(f"ZAP {component}/{operation}/{name} failed: {detail[:1000]}") from exc
        if not isinstance(payload, dict) or "code" in payload:
            raise ZapApiError(f"ZAP {component}/{operation}/{name} returned an error: {payload!r}")
        return payload

    def wait_ready(self) -> None:
        deadline = min(self.deadline, time.monotonic() + API_WAIT_SECONDS)
        while time.monotonic() < deadline:
            try:
                self.request("core", "view", "version")
                return
            except ZapDeadlineError:
                raise
            except (ZapApiError, OSError):
                time.sleep(min(1, max(0.05, deadline - time.monotonic())))
        if time.monotonic() >= self.deadline:
            raise ZapDeadlineError("DAST budget exhausted while waiting for ZAP startup")
        raise ZapApiError("ZAP API did not become ready before the startup timeout")


def _validate_origin(target_id: str, target_url: str) -> tuple[str, str, int]:
    expected = TARGET_ORIGINS.get(target_id)
    parsed = urlsplit(target_url)
    if (
        expected is None
        or parsed.scheme != "http"
        or parsed.hostname != expected[0]
        or parsed.port != expected[1]
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"Refusing unconfigured ZAP target origin: {target_url!r}")
    return parsed.scheme, expected[0], expected[1]


def _task_url(target_url: str, raw_path: str) -> str:
    origin = urlsplit(target_url)
    route = urlsplit(raw_path)
    if (
        not raw_path.startswith("/")
        or raw_path.startswith("//")
        or route.scheme
        or route.netloc
        or route.query
        or route.fragment
        or "\\" in route.path
        or any(part in {".", ".."} for part in route.path.split("/"))
        or any(ord(char) < 32 for char in route.path)
    ):
        raise ValueError(f"Refusing invalid route path from scan plan: {raw_path!r}")
    path = _FLASK_PATH_PARAMETER.sub("1", route.path)
    path = _EXPRESS_PATH_PARAMETER.sub("1", path)
    encoded_path = quote(path, safe="/-._~:@!$&'()*+,;=")
    return urlunsplit((origin.scheme, origin.netloc, encoded_path, "", ""))


def _request_data(task: dict[str, Any]) -> tuple[str, str | None, str | None]:
    method = str(task.get("method", "")).upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise ValueError(f"Unsupported route method in scan plan: {method!r}")

    parameters = task.get("parameters", [])
    if not isinstance(parameters, list):
        raise ValueError("Scan task parameters must be a list")
    values = [
        (str(parameter["name"]), "mitigata_scan")
        for parameter in parameters
        if isinstance(parameter, dict)
        and parameter.get("name")
        and parameter.get("source") in {"query", "path", "form"}
    ]
    base_url = str(task["url"])
    unsupported = sorted(
        {
            str(parameter.get("source"))
            for parameter in parameters
            if isinstance(parameter, dict)
            and parameter.get("source") in {"json", "header"}
        }
    )

    query = [
        (name, value)
        for name, value in values
        if any(
            parameter.get("name") == name and parameter.get("source") == "query"
            for parameter in parameters
            if isinstance(parameter, dict)
        )
    ]
    parts = urlsplit(base_url)
    existing_query = parse_qsl(parts.query, keep_blank_values=True)
    final_url = urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(existing_query + query), "")
    )
    if method == "GET":
        return final_url, method, None

    form_values = [
        (name, value)
        for name, value in values
        if any(
            parameter.get("name") == name and parameter.get("source") == "form"
            for parameter in parameters
            if isinstance(parameter, dict)
        )
    ]
    post_data = urlencode(form_values) if form_values else None
    return final_url, method, post_data


def _raw_seed_request(url: str, method: str, post_data: str | None) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    body = post_data or ""
    headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        "Connection: close",
    ]
    if post_data is not None:
        headers.append("Content-Type: application/x-www-form-urlencoded")
    headers.append(f"Content-Length: {len(body.encode('utf-8'))}")
    return "\r\n".join([*headers, "", body])


def _ensure_origin(url: str, expected: tuple[str, str, int]) -> None:
    parsed = urlsplit(url)
    if (parsed.scheme, parsed.hostname, parsed.port) != expected:
        raise ValueError(f"ZAP task URL escaped the configured target origin: {url!r}")


def _api_result(result: dict[str, Any], key: str) -> str:
    value = result.get(key)
    if value is None or isinstance(value, (dict, list)):
        raise ZapApiError(f"ZAP API response is missing {key!r}: {result!r}")
    return str(value)


def _scan_progress_complete(result: dict[str, Any]) -> bool:
    progress = result.get("scanProgress")
    if isinstance(progress, (int, str)):
        try:
            return int(progress) >= 100
        except ValueError:
            return False

    statuses: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "Plugin":
                    collect(child)
                elif isinstance(child, (dict, list)):
                    collect(child)
        elif isinstance(value, list):
            if len(value) >= 4 and isinstance(value[1], str) and value[1].isdigit():
                statuses.append(str(value[3]))
                return
            for child in value:
                collect(child)

    collect(progress)
    return bool(statuses) and all(status in {"Complete", "Skipped"} for status in statuses)


def _get_alerts(client: ZapClient, target_url: str) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    start = 0
    while True:
        result = client.request(
            "alert",
            "view",
            "alerts",
            baseurl=target_url,
            start=str(start),
            count="500",
        )
        batch = result.get("alerts", [])
        if not isinstance(batch, list):
            raise ZapApiError("ZAP alert API returned a non-list alerts value")
        alerts.extend(alert for alert in batch if isinstance(alert, dict))
        if len(batch) < 500:
            return alerts
        start += len(batch)


def _alert_key(alert: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        str(alert.get(field, ""))
        for field in ("pluginId", "url", "method", "param", "evidence")
    )


def _apply_policy(
    client: ZapClient,
    task: dict[str, Any],
    available_scanners: set[str],
) -> None:
    policy_name = "Default Policy"
    client.request("ascan", "action", "disableAllScanners", scanPolicyName=policy_name)
    if task["phase"] == "TARGETED":
        selected = set(task.get("zap_rule_ids", []))
        missing = selected - available_scanners
        if missing:
            raise ZapApiError(f"Mapped ZAP scanner IDs are not installed: {', '.join(sorted(missing))}")
        if selected:
            client.request(
                "ascan",
                "action",
                "enableScanners",
                ids=",".join(sorted(selected)),
                scanPolicyName=policy_name,
            )
    else:
        selected = BROAD_SCANNER_IDS - set(task.get("excluded_zap_rule_ids", []))
        missing = selected - available_scanners
        if missing:
            raise ZapApiError(
                f"Broad ZAP scanner IDs are not installed: {', '.join(sorted(missing))}"
            )
        if selected:
            client.request(
                "ascan",
                "action",
                "enableScanners",
                ids=",".join(sorted(selected)),
                scanPolicyName=policy_name,
            )


def _run_task(
    client: ZapClient,
    task: dict[str, Any],
    target_url: str,
    expected_origin: tuple[str, str, int],
    context_id: str,
    context_name: str,
    available_scanners: set[str],
    deadline: float,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    task["started_at"] = now
    task["status"] = "RUNNING"
    task_timeout = (
        TARGETED_TASK_TIMEOUT_SECONDS
        if task["phase"] == "TARGETED"
        else BROAD_TASK_TIMEOUT_SECONDS
    )
    task_timeout = min(task_timeout, TASK_TIMEOUT_SECONDS)
    task_deadline = min(deadline, time.monotonic() + task_timeout)
    task_url = _task_url(target_url, str(task["raw_url"]))
    task_url, method, post_data = _request_data({**task, "url": task_url})
    _ensure_origin(task_url, expected_origin)
    _apply_policy(client, task, available_scanners)
    client.request(
        "core",
        "action",
        "accessUrl",
        url=task_url,
        followRedirects="false",
    )
    if method and method != "GET":
        client.request(
            "core",
            "action",
            "sendRequest",
            request=_raw_seed_request(task_url, method, post_data),
            followRedirects="false",
        )
    params = {
        "url": task_url,
        "recurse": "false",
        "scanPolicyName": "Default Policy",
        "contextId": context_id,
        "method": method or "",
    }
    if post_data is not None:
        params["postData"] = post_data
    response = client.request("ascan", "action", "scan", **params)
    scan_id = _api_result(response, "scan")

    while time.monotonic() < task_deadline:
        progress = client.request("ascan", "view", "scanProgress", scanId=scan_id)
        if _scan_progress_complete(progress):
            task["progress"] = 100
            task["status"] = "COMPLETED"
            break
        time.sleep(min(POLL_INTERVAL_SECONDS, max(0.1, task_deadline - time.monotonic())))
    else:
        client.request("ascan", "action", "stop", scanId=scan_id)
        task["status"] = "TIMED_OUT"
        task["error"] = (
            "Scan budget cutoff reached"
            if time.monotonic() >= deadline
            else "Task timeout reached"
        )
    task["finished_at"] = datetime.now(timezone.utc).isoformat()


def execute(payload: dict[str, Any]) -> dict[str, Any]:
    api_key = payload.get("api_key")
    plan = payload.get("plan")
    if not isinstance(api_key, str) or not api_key or not isinstance(plan, dict):
        raise ValueError("Driver input must contain api_key and plan objects")
    target_id = str(plan["target_id"])
    target_url = str(plan["target_url"])
    scheme, host, port = _validate_origin(target_id, target_url)
    expected_origin = (scheme, host, port)
    deadline_at = datetime.fromisoformat(str(plan["deadline_at"]))
    budget = max(0.0, (deadline_at - datetime.now(timezone.utc)).total_seconds())
    deadline = time.monotonic() + max(0.0, budget - FINALIZATION_RESERVE_SECONDS)
    targeted = plan.get("targeted_tasks", [])
    broad = plan.get("broad_tasks", [])
    tasks = targeted + broad
    if not isinstance(tasks, list) or not all(isinstance(task, dict) for task in tasks):
        raise ValueError("Scan plan task lists must contain objects")

    started_at = datetime.now(timezone.utc).isoformat()
    plan["status"] = "RUNNING"
    alerts_by_key: dict[tuple[str, ...], dict[str, Any]] = {}
    cutoff = False
    client = ZapClient(api_key)
    if hasattr(client, "deadline"):
        client.deadline = deadline
    try:
        client.wait_ready()
        context_name = f"mitigata-{str(plan['scan_id'])[:24]}"
        context = client.request("context", "action", "newContext", contextName=context_name)
        context_id = _api_result(context, "contextId")
        scope_regex = rf"^{re.escape(scheme)}://{re.escape(host)}:{port}(?:/.*)?$"
        client.request(
            "context",
            "action",
            "includeInContext",
            contextName=context_name,
            regex=scope_regex,
        )
        client.request(
            "context",
            "action",
            "setContextInScope",
            contextName=context_name,
            booleanInScope="true",
        )
        scanner_result = client.request("ascan", "view", "scanners")
        scanner_list = scanner_result.get("scanners", [])
        if not isinstance(scanner_list, list):
            raise ZapApiError("ZAP scanner inventory was not a list")
        available_scanners = {
            str(scanner["id"])
            for scanner in scanner_list
            if isinstance(scanner, dict)
            and scanner.get("allDependenciesAvailable") == "true"
        }
    except ZapDeadlineError:
        cutoff = True
        context_id = ""
        context_name = ""
        available_scanners = set()
        for task in tasks:
            task["status"] = "SKIPPED_BUDGET"

    for phase_tasks in (() if cutoff else (targeted, broad)):
        for task in phase_tasks:
            if time.monotonic() >= deadline:
                task["status"] = "SKIPPED_BUDGET"
                cutoff = True
                continue
            if task["phase"] == "BROAD":
                completed_for_route = {
                    rule_id
                    for targeted_task in targeted
                    if targeted_task["route_id"] == task["route_id"]
                    and targeted_task["method"] == task["method"]
                    and targeted_task["status"] == "COMPLETED"
                    for rule_id in targeted_task.get("zap_rule_ids", [])
                }
                task["excluded_zap_rule_ids"] = sorted(completed_for_route)
            try:
                _run_task(
                    client,
                    task,
                    target_url,
                    expected_origin,
                    context_id,
                    context_name,
                    available_scanners,
                    deadline,
                )
            except (ZapApiError, ValueError, KeyError) as exc:
                task["status"] = "FAILED"
                task["error"] = str(exc)[:1000]
                task["finished_at"] = datetime.now(timezone.utc).isoformat()
            try:
                for alert in _get_alerts(client, target_url):
                    alerts_by_key[_alert_key(alert)] = alert
            except ZapDeadlineError:
                cutoff = True
            if task["status"] == "TIMED_OUT" and time.monotonic() >= deadline:
                cutoff = True
                break
        if cutoff:
            break

    for task in tasks:
        if task["status"] == "QUEUED":
            task["status"] = "SKIPPED_BUDGET" if cutoff or time.monotonic() >= deadline else "SKIPPED"
    plan["status"] = (
        "INCOMPLETE"
        if cutoff or any(task["status"] not in {"COMPLETED", "SKIPPED"} for task in tasks)
        else "COMPLETED"
    )
    finished_at = datetime.now(timezone.utc).isoformat()
    return {
        "target_id": target_id,
        "scan_id": plan["scan_id"],
        "scan_status": plan["status"],
        "started_at": started_at,
        "finished_at": finished_at,
        "alerts": list(alerts_by_key.values()),
        "tasks": tasks,
        "coverage": {
            "targeted_completed": sum(task["status"] == "COMPLETED" for task in targeted),
            "targeted_total": len(targeted),
            "broad_completed": sum(task["status"] == "COMPLETED" for task in broad),
            "broad_total": len(broad),
            "cutoff": cutoff,
        },
    }


def main() -> int:
    payload = json.load(sys.stdin)
    if not isinstance(payload, dict):
        raise ValueError("Driver input root must be a JSON object")
    print(json.dumps(execute(payload)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
