from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import quote, unquote, urlencode, urlsplit, urlunsplit

import httpx
import yaml

from .profile import load_target_profile
from .state import AlertState, ProbeRecord

CANARY_PAYLOADS: dict[str, list[str]] = {
    "sql_injection": ["'", '"'],
    "xss": [
        "<svg onload=console.log('CANARY_MITIGATA_2026')>",
        "<img src=x onerror=console.log('CANARY_MITIGATA_2026')>",
    ],
    "command_injection": [
        "; echo CANARY_MITIGATA_2026",
        "| echo CANARY_MITIGATA_2026",
    ],
    "ssti": ["{{7*7}}", "${7*7}"],
    "jwt_weak_secret": ["invalid.canary.token", "invalid.second.canary.token"],
    "eval_injection": ["1+1", "2+2"],
    "insecure_deserialisation": ["\\x80\\x04K\\x01.", "\\x80\\x04K\\x02."],
    "weak_hash": ["test", "password"],
}

EVIDENCE_SIGNALS: dict[str, list[str]] = {
    "sql_injection": ["operationalerror", "sqlite3", "syntax error"],
    "xss": ["<svg", "<img", "onload=", "onerror="],
    "command_injection": ["canary_mitigata_2026"],
    "ssti": ["49", "jinja2", "templateerror"],
    "jwt_weak_secret": ["authenticated", "admin", "unauthorized"],
    "eval_injection": ["2", "4"],
    "insecure_deserialisation": ["pickle", "unpicklingerror"],
    "weak_hash": ["md5", "sha1", "hash"],
}
_NON_PROBEABLE_SINKS = {"hardcoded_secret"}

_PATH_PLACEHOLDER = re.compile(
    r"<(?:(?:int|float|string|path|uuid):)?([A-Za-z_][A-Za-z0-9_]*)>"
    r"|:([A-Za-z_][A-Za-z0-9_]*)"
    r"|\{([A-Za-z_][A-Za-z0-9_]*)\}"
)
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_BLOCKED_HEADERS = {
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "host",
    "proxy-authorization",
    "transfer-encoding",
}
_NON_RETRYABLE_ERRORS = {
    "invalid_target_profile",
    "unsafe_http_method",
    "invalid_route",
    "invalid_parameter",
    "invalid_parameter_source",
    "unsupported_sink_type",
    "path_parameter_not_found",
}
_MAX_RESPONSE_BYTES = 500


def probe_generator(state: AlertState) -> AlertState:
    if state["sink_type"] in _NON_PROBEABLE_SINKS:
        return {
            **state,
            "error": "no_safe_runtime_probe_available",
            "label": "UNVERIFIED",
        }
    payloads = CANARY_PAYLOADS.get(state["sink_type"])
    if not payloads:
        return {
            **state,
            "error": "unsupported_sink_type",
            "label": "UNVERIFIED",
        }
    variant = min(max(state["probe_variant"], 0), len(payloads) - 1)
    return {**state, "probe_variant": variant, "probe_payload": payloads[variant]}


def _materialize_route(
    route: str,
    parameter: str,
    parameter_source: str,
    payload: str,
) -> tuple[str, str]:
    try:
        parsed = urlsplit(route)
    except ValueError as exc:
        raise ValueError("invalid_route") from exc
    path = parsed.path
    if not path.startswith("/") or path.startswith("//") or "\\" in path:
        raise ValueError("invalid_route")
    if any(ord(char) < 0x20 for char in path):
        raise ValueError("invalid_route")

    for segment in path.split("/"):
        decoded = unquote(segment)
        if decoded in {".", ".."} or "/" in decoded or "\\" in decoded:
            raise ValueError("invalid_route")

    found_path_parameter = False

    def replace(match: re.Match[str]) -> str:
        nonlocal found_path_parameter
        name = next(group for group in match.groups() if group is not None)
        if parameter_source == "path" and name in {parameter, "param"}:
            value = payload
            found_path_parameter = True
        else:
            value = "1" if name.lower() in {"id", "index", "page", "number"} else "test"
        return quote(value, safe="")

    materialized_path = _PATH_PLACEHOLDER.sub(replace, path)
    if parameter_source == "path" and not found_path_parameter:
        raise ValueError("path_parameter_not_found")
    query = parsed.query
    if parameter_source == "query":
        separator = "&" if query else ""
        query = f"{query}{separator}{urlencode({parameter: payload})}"
    return materialized_path, query


def build_local_probe_url(
    origin: str,
    route: str,
    parameter: str,
    parameter_source: str,
    payload: str,
) -> str:
    """Use only the configured origin while retaining the finding's route/query."""
    if not parameter or any(ord(char) < 0x20 for char in parameter):
        raise ValueError("invalid_parameter")
    if parameter_source not in {"path", "query", "form", "json", "header"}:
        raise ValueError("invalid_parameter_source")
    base = urlsplit(origin)
    if base.scheme not in {"http", "https"} or not base.netloc or base.path:
        raise ValueError("invalid_target_profile")
    path, query = _materialize_route(route, parameter, parameter_source, payload)
    return urlunsplit((base.scheme, base.netloc, path, query, ""))


def _record(
    state: AlertState,
    *,
    response: str | None = None,
    status: int | None = None,
    error: str | None = None,
) -> list[ProbeRecord]:
    record: ProbeRecord = {
        "variant": state["probe_variant"],
        "payload": state["probe_payload"],
    }
    if response is not None:
        record["response_preview"] = response[:200]
    if status is not None:
        record["status"] = status
    if error is not None:
        record["error"] = error
    return [*state["probe_history"], record]


async def runtime_executor(state: AlertState) -> AlertState:
    if state.get("error"):
        return state
    try:
        profile = load_target_profile(state["target_id"])
    except (OSError, ValueError, yaml.YAMLError) as exc:
        error = f"invalid_target_profile: {str(exc)[:160]}"
        return {
            **state,
            "error": error,
            "label": "UNVERIFIED",
            "probe_history": _record(state, error=error),
        }

    method = state["method"].upper()
    if method not in {"GET", "HEAD", "OPTIONS", "POST"}:
        error = "unsafe_http_method"
        return {
            **state,
            "error": error,
            "label": "UNVERIFIED",
            "probe_history": _record(state, error=error),
        }

    source = state["parameter_source"]
    parameter = state["parameter"]
    if source == "header" and (
        not _HEADER_NAME.fullmatch(parameter)
        or parameter.lower() in _BLOCKED_HEADERS
    ):
        error = "invalid_parameter"
        return {
            **state,
            "error": error,
            "label": "UNVERIFIED",
            "probe_history": _record(state, error=error),
        }
    try:
        url = build_local_probe_url(
            profile.origin,
            state["route"],
            parameter,
            source,
            state["probe_payload"],
        )
    except ValueError as exc:
        error = str(exc)
        return {
            **state,
            "error": error,
            "label": "UNVERIFIED",
            "probe_history": _record(state, error=error),
        }

    request_values: dict[str, Any] = {}
    if source == "form":
        request_values["data"] = {parameter: state["probe_payload"]}
    elif source == "json":
        request_values["json"] = {parameter: state["probe_payload"]}
    elif source == "header":
        request_values["headers"] = {parameter: state["probe_payload"]}

    try:
        async with asyncio.timeout(2.0):
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(2.0),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(method, url, **request_values) as response:
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        remaining = _MAX_RESPONSE_BYTES - len(body)
                        if remaining <= 0:
                            break
                        body.extend(chunk[:remaining])
                        if len(body) >= _MAX_RESPONSE_BYTES:
                            break
                    response_text = bytes(body).decode("utf-8", errors="replace")
                    status = response.status_code
        return {
            **state,
            "http_status": status,
            "http_response": response_text,
            "error": None,
            "probe_history": _record(state, response=response_text, status=status),
        }
    except (TimeoutError, httpx.TimeoutException):
        error = "probe_timeout"
    except httpx.RequestError as exc:
        error = f"probe_request_error: {str(exc)[:160]}"
    return {
        **state,
        "error": error,
        "probe_history": _record(state, error=error),
    }


def response_evaluator(state: AlertState) -> AlertState:
    if state.get("error"):
        return state
    response = state.get("http_response") or ""
    sink_type = state["sink_type"]
    lowered = response.casefold()
    signals = EVIDENCE_SIGNALS.get(sink_type, [])
    found = [signal for signal in signals if signal.casefold() in lowered]
    if sink_type == "ssti":
        found = [
            signal
            for signal in found
            if signal != "49"
            or (
                re.search(r"(?<!\d)49(?!\d)", response) is not None
                and "{{7*7}}" not in response
                and "${7*7}" not in response
            )
        ]
    if sink_type == "eval_injection":
        expected = {"1+1": "2", "2+2": "4"}.get(state["probe_payload"])
        found = [signal for signal in found if expected and response.strip() == expected]
    if found:
        evidence = f"Response contained verification signals: {', '.join(found)}"
        return {**state, "evidence": evidence, "label": "Confirmed"}
    return {**state, "label": "Code only"}


def retry_evaluator(state: AlertState) -> AlertState:
    return {
        **state,
        "probe_variant": state["probe_variant"] + 1,
        "error": None,
        "http_response": None,
        "http_status": None,
        "evidence": None,
    }


def should_retry(state: AlertState) -> str:
    error = state.get("error") or ""
    error_code = error.split(":", 1)[0]
    if (
        state["label"] == "Code only"
        and state["probe_variant"] == 0
        and error_code not in _NON_RETRYABLE_ERRORS
    ):
        return "retry"
    return "end"
