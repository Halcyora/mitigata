from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..ast_mapper.route_schema import RouteNode
from .correlator import candidate_match_level
from .deduplication import deduplicate_findings, finding_deduplication_key
from .schema import UnifiedFinding


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _alert_identity(finding: UnifiedFinding) -> tuple[str, ...]:
    return finding_deduplication_key(finding)


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
        self._sast_findings = deduplicate_findings(sast_findings, self.routes)
        self._dast_seen: dict[str, UnifiedFinding] = {}
        self._correlated_by_sast: dict[str, UnifiedFinding] = {}
        self._runtime_only: dict[str, UnifiedFinding] = {}
        self.events: list[CorrelationEvent] = []

    def _record(self, kind: str, message: str, *, finding: UnifiedFinding | None = None, **payload: Any) -> None:
        event = CorrelationEvent(kind=kind, message=message, finding_id=finding.id if finding else None, finding=finding, payload=dict(payload))
        self.events.append(event)

    def _sast_candidates(
        self, dast_finding: UnifiedFinding
    ) -> list[tuple[UnifiedFinding, RouteNode, str]]:
        matches: dict[str, tuple[UnifiedFinding, RouteNode, str]] = {}
        for route in self.routes:
            for sast_finding in self._sast_findings:
                level = candidate_match_level(route, sast_finding, dast_finding)
                if level is None:
                    continue
                previous = matches.get(sast_finding.id)
                if previous is None or (
                    previous[2] == "Corroborated" and level == "Confirmed"
                ):
                    matches[sast_finding.id] = (sast_finding, route, level)
        return list(matches.values())

    def ingest_alert(self, finding: UnifiedFinding) -> tuple[str, UnifiedFinding | None]:
        if finding.source != "dast":
            raise ValueError("Incremental correlation only accepts DAST findings")
        identity = _alert_identity(finding)
        previous = self._dast_seen.get(str(identity))
        if previous is not None:
            combined = deduplicate_findings([previous, finding], self.routes)[0]
            self._dast_seen[str(identity)] = combined
            if previous.id in self._runtime_only:
                self._runtime_only[previous.id] = combined.model_copy(
                    update={"label": "Runtime only"}
                )
            for sast_id, correlated in list(self._correlated_by_sast.items()):
                if previous.id not in correlated.merged_from:
                    continue
                self._correlated_by_sast[sast_id] = correlated.model_copy(
                    update={
                        "merged_from": list(
                            dict.fromkeys([*correlated.merged_from, *combined.merged_from])
                        ),
                        "routes": list(
                            dict.fromkeys([*correlated.routes, *combined.routes])
                        ),
                        "evidence": combined.evidence or correlated.evidence,
                    }
                )
            self._record(
                "DEDUPLICATED_ALERT",
                "Duplicate DAST finding merged into the existing issue",
                finding=combined,
            )
            return "deduplicated", combined
        self._dast_seen[str(identity)] = finding

        candidates = self._sast_candidates(finding)
        if not candidates:
            runtime_only = finding.model_copy(update={"label": "Runtime only"})
            self._runtime_only[finding.id] = runtime_only
            self._record(
                "RUNTIME_ONLY",
                "No target, CWE, route, method, and code-scope SAST match",
                finding=runtime_only,
            )
            return "runtime_only", runtime_only

        candidates.sort(
            key=lambda item: (
                0 if item[2] == "Confirmed" else 1,
                item[0].file or "",
                item[0].line or 0,
                item[0].id,
            )
        )
        candidate, route, level = candidates[0]
        existing = self._correlated_by_sast.get(candidate.id)
        if existing is not None and not (
            existing.label == "Corroborated" and level == "Confirmed"
        ):
            runtime_only = finding.model_copy(update={"label": "Runtime only"})
            self._runtime_only[finding.id] = runtime_only
            self._record("UNMATCHED_DAST", "DAST alert could not consume an unclaimed SAST finding", finding=runtime_only)
            return "runtime_only", runtime_only

        merged_from = list(
            dict.fromkeys(
                [
                    *(existing.merged_from if existing else candidate.merged_from),
                    candidate.id,
                    *finding.merged_from,
                    finding.id,
                ]
            )
        )
        correlated = candidate.model_copy(
            update={
                "label": level,
                "url": finding.url,
                "method": finding.method,
                "parameter": finding.parameter,
                "parameter_source": finding.parameter_source,
                "evidence": finding.evidence,
                "http_status": finding.http_status,
                "merged_from": merged_from,
                "confidence": 0.95 if level == "Confirmed" else 0.72,
                "reason": (
                    "Matched target, CWE, route, method, code scope, and request "
                    "parameter/source."
                    if level == "Confirmed"
                    else "Matched target, CWE, route, method, and code scope; "
                    "request input evidence is incomplete or ambiguous."
                ),
                "routes": list(
                    dict.fromkeys(
                        [*(existing.routes if existing else []), route.normalized_url]
                    )
                ),
            }
        )
        self._correlated_by_sast[candidate.id] = correlated
        event_kind = "CONFIRMED" if level == "Confirmed" else "CORROBORATED"
        self._record(
            event_kind,
            "SAST and DAST findings matched"
            if level == "Confirmed"
            else "SAST and DAST route evidence matched; input evidence is incomplete",
            finding=correlated,
        )
        return level.lower(), correlated

    def finalize(self) -> list[UnifiedFinding]:
        merged: list[UnifiedFinding] = []
        correlated_ids = set(self._correlated_by_sast)
        dast_ids = {finding.id for finding in self._dast_seen.values()}
        matched_dast_ids = {
            merged_id
            for correlated in self._correlated_by_sast.values()
            for merged_id in correlated.merged_from
            if merged_id in dast_ids
        }
        for finding in self._sast_findings:
            if finding.id in correlated_ids:
                merged.append(self._correlated_by_sast[finding.id])
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

        label_rank = {
            "Confirmed": 0,
            "Corroborated": 1,
            "Code only": 2,
            "Runtime only": 3,
        }
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
