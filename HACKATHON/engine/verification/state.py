from __future__ import annotations

from typing import Literal, TypedDict

from ..ingestion.schema import UnifiedFinding

VerificationLabel = Literal["Confirmed", "Code only", "Runtime only", "UNVERIFIED"]


class ProbeRecord(TypedDict, total=False):
    variant: int
    payload: str
    status: int
    response_preview: str
    error: str
    location: str


class AlertState(TypedDict):
    finding_id: str
    target_id: str
    route: str
    method: str
    parameter: str
    parameter_source: str
    sink_type: str
    probe_payload: str
    probe_variant: int
    http_status: int | None
    http_response: str | None
    http_location: str | None
    evidence: str | None
    label: VerificationLabel
    error: str | None
    probe_history: list[ProbeRecord]


def new_alert_state(
    *,
    finding_id: str,
    target_id: str,
    route: str,
    method: str,
    parameter: str,
    parameter_source: str,
    sink_type: str,
) -> AlertState:
    """Create a fully initialized state for one source finding."""
    required = {
        "finding_id": finding_id,
        "target_id": target_id,
        "route": route,
        "method": method,
        "parameter": parameter,
        "parameter_source": parameter_source,
        "sink_type": sink_type,
    }
    if any(not isinstance(value, str) or not value.strip() for value in required.values()):
        raise ValueError("Verification state fields must be non-empty strings")

    return {
        **required,
        "probe_payload": "",
        "probe_variant": 0,
        "http_status": None,
        "http_response": None,
        "http_location": None,
        "evidence": None,
        "label": "Code only",
        "error": None,
        "probe_history": [],
    }


def state_from_finding(finding: UnifiedFinding) -> AlertState:
    """Build verification state from a normalized finding with complete request metadata."""
    if finding.source != "sast":
        raise ValueError("Only SAST findings can start runtime verification")
    if finding.label not in {None, "Code only"}:
        raise ValueError(
            "Only unverified Code only findings can start runtime verification"
        )
    values = {
        "finding_id": finding.id,
        "target_id": finding.target_id,
        "route": finding.url or finding.route,
        "method": finding.method,
        "parameter": finding.parameter,
        "parameter_source": finding.parameter_source,
        "sink_type": finding.sink_type,
    }
    missing = [key for key, value in values.items() if not value]
    if missing:
        raise ValueError(
            "Finding lacks verification metadata: " + ", ".join(sorted(missing))
        )
    return new_alert_state(
        finding_id=finding.id,
        target_id=finding.target_id,
        route=finding.url or finding.route or "",
        method=finding.method or "",
        parameter=finding.parameter or "",
        parameter_source=finding.parameter_source or "",
        sink_type=finding.sink_type or "",
    )
