from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from ..ast_mapper.route_schema import RouteNode
from .schema import UnifiedFinding


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _alert_identity(finding: UnifiedFinding) -> tuple[str, ...]:
    return (
        str(finding.target_id),
        str(finding.cwe_id),
        str(finding.url or ""),
        str(finding.method or ""),
        str(finding.parameter or ""),
        str(finding.parameter_source or ""),
        str(finding.evidence or ""),
    )


def _candidate_match(route: RouteNode, sast_finding: UnifiedFinding, dast_finding: UnifiedFinding) -> bool:
    if route.target_id != sast_finding.target_id or route.target_id != dast_finding.target_id:
        return False
    if dast_finding.cwe_id != sast_finding.cwe_id:
        return False
    if not dast_finding.url or not dast_finding.method:
        return False
    parsed = urlparse(dast_finding.url)
    if not parsed.path or not route.matches_path(parsed.path):
        return False
    if not route.matches_method(dast_finding.method):
        return False
    if not route.contains_location(sast_finding.file, sast_finding.line):
        return False
    if not dast_finding.parameter or not dast_finding.parameter_source:
        return False
    if not any(
        read.name == dast_finding.parameter and read.source == dast_finding.parameter_source
        for read in route.input_parameters
    ):
        return False
    return True


@dataclass
class CorrelationEvent:
    kind: str
    message: str
    finding_id: str | None = None
    finding: UnifiedFinding | None = None
    created_at: str = field(default_factory=_utc_now)
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "message": self.message,
            "finding_id": self.finding_id,
            "finding": self.finding.model_dump() if self.finding else None,
            "created_at": self.created_at,
            "payload": self.payload,
        }


class IncrementalCorrelator:
    def __init__(
        self,
        sast_findings: list[UnifiedFinding],
        routes: list[RouteNode],
        *,
        scan_id: str = "scan",
    ) -> None:
        self.scan_id = scan_id
        self.routes = list(routes)
        self._sast_findings = list(sast_findings)
        self._dast_seen: dict[str, UnifiedFinding] = {}
        self._used_dast_ids: set[str] = set()
        self._used_sast_ids: set[str] = set()
        self._confirmed_by_sast: dict[str, UnifiedFinding] = {}
        self._runtime_only: dict[str, UnifiedFinding] = {}
        self.events: list[CorrelationEvent] = []

    def _record(self, kind: str, message: str, *, finding: UnifiedFinding | None = None, **payload: Any) -> None:
        event = CorrelationEvent(kind=kind, message=message, finding_id=finding.id if finding else None, finding=finding, payload=dict(payload))
        self.events.append(event)

    def _sast_candidates(self, dast_finding: UnifiedFinding) -> list[UnifiedFinding]:
        matches: list[UnifiedFinding] = []
        for route in self.routes:
            for sast_finding in self._sast_findings:
                if not _candidate_match(route, sast_finding, dast_finding):
                    continue
                matches.append(sast_finding)
        deduped: list[UnifiedFinding] = []
        seen: set[str] = set()
        for finding in matches:
            if finding.id in seen:
                continue
            seen.add(finding.id)
            deduped.append(finding)
        return deduped

    def ingest_alert(self, finding: UnifiedFinding) -> tuple[str, UnifiedFinding | None]:
        if finding.source != "dast":
            raise ValueError("Incremental correlation only accepts DAST findings")
        identity = _alert_identity(finding)
        previous = self._dast_seen.get(str(identity))
        if previous is not None:
            self._record("DEDUPLICATED_ALERT", "Duplicate DAST finding ignored", finding=previous)
            return "deduplicated", previous
        self._dast_seen[str(identity)] = finding

        candidates = self._sast_candidates(finding)
        if not candidates:
            runtime_only = finding.model_copy(update={"label": "Runtime only"})
            self._runtime_only[finding.id] = runtime_only
            self._record("RUNTIME_ONLY", "No strict SAST match", finding=runtime_only)
            return "runtime_only", runtime_only

        candidate = sorted(candidates, key=lambda item: (item.file or "", item.line or 0, item.id))[0]
        if candidate.id in self._used_sast_ids:
            runtime_only = finding.model_copy(update={"label": "Runtime only"})
            self._runtime_only[finding.id] = runtime_only
            self._record("UNMATCHED_DAST", "DAST alert could not consume an unclaimed SAST finding", finding=runtime_only)
            return "runtime_only", runtime_only

        self._used_sast_ids.add(candidate.id)
        self._used_dast_ids.add(finding.id)
        confirmed = candidate.model_copy(
            update={
                "label": "Confirmed",
                "url": finding.url,
                "method": finding.method,
                "parameter": finding.parameter,
                "parameter_source": finding.parameter_source,
                "evidence": finding.evidence,
                "http_status": finding.http_status,
                "merged_from": [candidate.id, finding.id],
                "confidence": 0.95,
                "routes": [
                    route.normalized_url
                    for route in self.routes
                    if _candidate_match(route, candidate, finding)
                ],
            }
        )
        self._confirmed_by_sast[candidate.id] = confirmed
        self._record("CONFIRMED", "Strict correlation matched a SAST and DAST finding", finding=confirmed)
        return "confirmed", confirmed

    def finalize(self) -> list[UnifiedFinding]:
        merged: list[UnifiedFinding] = []
        confirmed_ids = set(self._confirmed_by_sast)
        matched_dast_ids = {
            merged_id
            for confirmed in self._confirmed_by_sast.values()
            for merged_id in (confirmed.merged_from[1:] if isinstance(confirmed.merged_from, list) and len(confirmed.merged_from) > 1 else [])
        }
        for finding in self._sast_findings:
            if finding.id in confirmed_ids:
                merged.append(self._confirmed_by_sast[finding.id])
                continue
            merged.append(
                finding.model_copy(
                    update={
                        "label": "Code only",
                        "reachable": any(
                            route.target_id == finding.target_id
                            and route.resolved
                            and route.contains_location(finding.file, finding.line)
                            for route in self.routes
                        ),
                    }
                )
            )

        for finding in self._dast_seen.values():
            if finding.id in matched_dast_ids:
                continue
            merged.append(finding.model_copy(update={"label": "Runtime only"}))

        label_rank = {"Confirmed": 0, "Code only": 1, "Runtime only": 2}
        merged.sort(key=lambda item: (label_rank.get(item.label or "Code only", 1), item.file or "", item.line or 0, item.id))
        return merged


def correlate_incremental(
    sast: list[UnifiedFinding],
    dast: list[UnifiedFinding],
    routes: list[RouteNode],
    *,
    scan_id: str = "scan",
) -> list[UnifiedFinding]:
    correlator = IncrementalCorrelator(sast, routes, scan_id=scan_id)
    for finding in dast:
        correlator.ingest_alert(finding)
    return correlator.finalize()
