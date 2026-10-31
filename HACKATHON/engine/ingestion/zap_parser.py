from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .schema import UnifiedFinding


ZAP_SINK_MAP = {
    "89": "sql_injection",
    "78": "command_injection",
    "79": "xss",
    "94": "ssti",
    "502": "insecure_deserialisation",
    "200": "information_disclosure",
    "347": "jwt_weak_secret",
}

ZAP_PARAM_SOURCE_MAP = {
    "URL_PATH": "path",
    "GET": "query",
    "POST_DATA": "form",
    "JSON": "json",
    "HEADER": "header",
}

_RISK_NORMALISE = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
    "info": "INFO",
}


def _cwe_id(value: Any) -> str:
    raw = str(value or "").strip()
    if raw.upper().startswith("CWE-"):
        raw = raw[4:].split(":", 1)[0].strip()
    if raw.isdigit() and int(raw) > 0:
        return f"CWE-{int(raw)}"
    return "CWE-UNKNOWN"


def _severity(alert: dict[str, Any]) -> str:
    risk = alert.get("riskdesc") or alert.get("risk") or "Medium"
    normalized = str(risk).strip().split(" ", 1)[0].lower()
    return _RISK_NORMALISE.get(normalized, normalized.upper() or "MEDIUM")


def parse_zap_json(path: str | Path, target_id: str) -> list[UnifiedFinding]:
    """Parse standard ZAP alert JSON (including the nested site format)."""
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("ZAP JSON root must be an object")

    alerts = data.get("alerts")
    if alerts is not None and not isinstance(alerts, list):
        raise ValueError("ZAP JSON 'alerts' must be a list")
    if alerts is None or not alerts:
        alerts = []
        sites = data.get("site", [])
        if not isinstance(sites, list):
            raise ValueError("ZAP JSON 'site' must be a list")
        for site in sites:
            if not isinstance(site, dict):
                raise ValueError("Each ZAP site entry must be an object")
            site_alerts = site.get("alerts", [])
            if not isinstance(site_alerts, list):
                raise ValueError("ZAP site 'alerts' must be a list")
            alerts.extend(site_alerts)
    if not isinstance(alerts, list):
        raise ValueError("ZAP JSON 'alerts' must be a list")

    findings: list[UnifiedFinding] = []
    for index, alert in enumerate(alerts):
        if not isinstance(alert, dict):
            raise ValueError(f"ZAP alert at index {index} must be an object")
        cwe_id = _cwe_id(alert.get("cweid"))
        raw_evidence = alert.get("evidence", "")
        evidence = str(raw_evidence)[:500] if raw_evidence is not None else ""
        param_type = str(alert.get("paramType") or "").upper()
        findings.append(
            UnifiedFinding(
                target_id=target_id,
                source="dast",
                cwe_id=cwe_id,
                url=alert.get("url"),
                method=alert.get("method"),
                parameter=alert.get("param") or None,
                parameter_source=ZAP_PARAM_SOURCE_MAP.get(param_type),
                evidence=evidence,
                http_status=alert.get("statusCode"),
                rule_id=(
                    str(alert.get("pluginId") or alert.get("alertRef"))
                    if alert.get("pluginId") or alert.get("alertRef")
                    else None
                ),
                severity=_severity(alert),
                sink_type=ZAP_SINK_MAP.get(cwe_id.removeprefix("CWE-"), "unknown"),
                label="Runtime only",
            )
        )
    return findings
