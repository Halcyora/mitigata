from __future__ import annotations

from pathlib import PurePosixPath
from urllib.parse import urlparse

from ..ast_mapper.route_schema import RouteNode
from .schema import UnifiedFinding


# These ZAP alerts describe target-wide response policies. The same issue is
# commonly reported once for every URL and method that observes the policy.
_TARGET_WIDE_POLICY_RULES = {"10038", "10098"}


def finding_deduplication_key(finding: UnifiedFinding) -> tuple[str, ...]:
    """Return a stable issue key, excluding run-specific IDs and evidence text."""
    if finding.source == "sast":
        raw_location = (finding.file or "").replace("\\", "/")
        location = PurePosixPath(raw_location).as_posix() if raw_location else ""
        if location and finding.line is not None:
            # Multiple rules can report the same CWE at the same source line.
            return ("sast", finding.target_id, finding.cwe_id, location, str(finding.line))
        return (
            "sast",
            finding.target_id,
            finding.cwe_id,
            finding.rule_id or "",
            location,
            str(finding.line or ""),
            finding.id,
        )

    rule_id = finding.rule_id or ""
    if rule_id in _TARGET_WIDE_POLICY_RULES and not finding.parameter:
        return ("dast-policy", finding.target_id, finding.cwe_id, rule_id)

    path = urlparse(finding.url or "").path.rstrip("/") or "/"
    return (
        "dast",
        finding.target_id,
        finding.cwe_id,
        rule_id,
        path,
        (finding.method or "").strip().upper(),
        finding.parameter or "",
        finding.parameter_source or "",
    )


def _merge_routes(
    findings: list[UnifiedFinding], routes: list[RouteNode]
) -> list[str]:
    merged: list[str] = []
    for finding in findings:
        merged.extend(finding.routes)
        if not finding.url:
            continue
        path = urlparse(finding.url).path
        matches = [
            route
            for route in routes
            if route.target_id == finding.target_id
            and route.matches_path(path)
            and (
                finding.rule_id in _TARGET_WIDE_POLICY_RULES
                or route.matches_method(finding.method)
            )
        ]
        if matches:
            merged.extend(route.normalized_url for route in matches)
        elif path:
            merged.append(path)
    return list(dict.fromkeys(merged))


def deduplicate_findings(
    findings: list[UnifiedFinding], routes: list[RouteNode] | None = None
) -> list[UnifiedFinding]:
    """Collapse repeated scanner reports while preserving their source IDs/routes.

    SAST findings collapse by target, CWE, and source location. DAST findings
    collapse by target, CWE, rule, and request surface. ZAP's CORS/CSP policy
    alerts collapse across URLs because they describe one target-wide setting.
    """
    route_list = routes or []
    deduped: list[UnifiedFinding] = []
    index_by_key: dict[tuple[str, ...], int] = {}

    for finding in findings:
        key = finding_deduplication_key(finding)
        existing_index = index_by_key.get(key)
        if existing_index is None:
            index_by_key[key] = len(deduped)
            deduped.append(finding)
            continue

        existing = deduped[existing_index]
        merged_ids = list(
            dict.fromkeys(
                [
                    *existing.merged_from,
                    existing.id,
                    *finding.merged_from,
                    finding.id,
                ]
            )
        )
        merged_routes = _merge_routes([existing, finding], route_list)
        evidence_parts = list(
            dict.fromkeys(
                item
                for item in (existing.evidence, finding.evidence)
                if item
            )
        )
        deduped[existing_index] = existing.model_copy(
            update={
                "merged_from": merged_ids,
                "routes": merged_routes,
                "evidence": "\n--- duplicate alert evidence ---\n".join(evidence_parts)[:500]
                if evidence_parts
                else None,
                "reason": (
                    f"Collapsed {len(merged_ids)} duplicate scanner reports "
                    "for the same target, weakness, and source/request surface."
                ),
            }
        )

    return deduped
