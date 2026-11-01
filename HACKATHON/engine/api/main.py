from __future__ import annotations

import asyncio
import ast
import json
import logging
import os
import threading
from collections.abc import AsyncIterator
from typing import Literal

import yaml
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from ..compliance.mapping import FRAMEWORK_ORDER, map_finding_to_frameworks
from ..compliance.risk_calculator import calculate_inr_exposure
from ..ingestion.schema import UnifiedFinding
from ..verification.nodes import CANARY_PAYLOADS, NON_PROBEABLE_SINKS
from ..verification.state import state_from_finding
from ..verification.workflow import iter_verification_states
from ..patch_engine.llm_patcher import (
    PatchGenerationError,
    apply_unified_diff,
    generate_patch,
)
from ..dast_planner.planner import build_scan_plan
from ..verification.profile import load_target_profile
from ..verification_store import (
    clear_verification_result,
    clear_target_verifications,
    save_confirmed_result,
)
from ..scan_manager.jobs import ScanAlreadyRunning, scan_jobs
from ..scan_manager.history import compare_finding_snapshots
from .graph import (
    GraphResponse,
    _profile_data,
    _routes_and_stats,
    _source_dir,
    clear_graph_snapshot_cache,
    get_graph_snapshot,
)

logger = logging.getLogger(__name__)
_PATCH_PREVIEWS: dict[tuple[str, str], str] = {}
_PATCH_PREVIEW_LOCK = threading.Lock()

TargetId = Literal["flask_demo", "juice_shop"]


class PatchRequest(BaseModel):
    finding_id: str
    target_id: TargetId


class PatchApplyRequest(PatchRequest):
    patch: str = Field(min_length=1, max_length=20_000)


class ScanStartRequest(BaseModel):
    target_id: TargetId
    scan_type: Literal["sast", "dast"]


class ComplianceResponse(BaseModel):
    target_id: TargetId
    records_at_risk: int
    findings: list[dict[str, object]]
    summary: dict[str, int]


app = FastAPI(title="Mitigata correlation engine")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/targets")
def list_targets() -> list[str]:
    return ["flask_demo", "juice_shop"]


@app.get("/api/graph", response_model=GraphResponse)
def get_graph(target_id: TargetId) -> GraphResponse:
    return get_graph_snapshot(target_id).response


@app.get("/api/compliance", response_model=ComplianceResponse)
def get_compliance(
    target_id: TargetId, records_at_risk: int = Query(default=10_000, ge=0, le=100_000_000)
) -> ComplianceResponse:
    findings = get_graph_snapshot(target_id).findings
    rows: list[dict[str, object]] = []
    counts = {framework: 0 for framework in FRAMEWORK_ORDER}
    for finding in findings:
        payload = finding.model_dump(mode="json")
        payload["compliance"] = map_finding_to_frameworks(finding)
        payload["risk"] = calculate_inr_exposure(finding, records_at_risk)
        mapping = payload["compliance"]
        if mapping:
            for framework in mapping:
                counts[framework] += 1
        rows.append(payload)
    return ComplianceResponse(
        target_id=target_id,
        records_at_risk=records_at_risk,
        findings=rows,
        summary=counts,
    )


@app.post("/api/patch")
def create_patch(request: PatchRequest) -> dict[str, object]:
    snapshot = get_graph_snapshot(request.target_id)
    finding = next((item for item in snapshot.findings if item.id == request.finding_id), None)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found for target")
    if not finding.file or not finding.line or not finding.sink_type:
        raise HTTPException(status_code=422, detail="Finding lacks source location or sink type")
    source_root = _source_dir(_profile_data(request.target_id).get("source_dir"))
    if source_root is None:
        raise HTTPException(status_code=422, detail="Target source tree is unavailable")
    source_path = (source_root / finding.file).resolve()
    if not source_path.is_relative_to(source_root) or not source_path.is_file():
        raise HTTPException(status_code=422, detail="Finding source file is unavailable")
    try:
        source_lines = source_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise HTTPException(status_code=422, detail="Unable to read finding source file") from exc
    start, end = max(0, finding.line - 41), min(len(source_lines), finding.line + 40)
    context = "\n".join(f"{line_no + 1}: {source_lines[line_no]}" for line_no in range(start, end))
    try:
        result = generate_patch(
            finding.sink_type,
            finding.file,
            finding.line,
            context,
            cwe_id=finding.cwe_id,
        )
    except PatchGenerationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if result.kind == "unified_diff":
        with _PATCH_PREVIEW_LOCK:
            _PATCH_PREVIEWS[(request.target_id, finding.id)] = result.content
    return {
        "finding_id": finding.id,
        "target_id": request.target_id,
        "sink_type": finding.sink_type,
        "file": finding.file,
        "line": finding.line,
        "patch": result.content,
        "kind": result.kind,
        "source": result.source,
        "model": result.model,
        "applied": False,
    }


@app.post("/api/patch/apply")
def apply_patch_endpoint(request: PatchApplyRequest) -> dict[str, object]:
    snapshot = get_graph_snapshot(request.target_id)
    finding = next((item for item in snapshot.findings if item.id == request.finding_id), None)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found for target")
    if not finding.file:
        raise HTTPException(status_code=422, detail="Finding has no source file")
    source_root = _source_dir(_profile_data(request.target_id).get("source_dir"))
    if source_root is None:
        raise HTTPException(status_code=422, detail="Target source tree is unavailable")
    source_path = (source_root / finding.file).resolve()
    if not source_path.is_relative_to(source_root) or not source_path.is_file():
        raise HTTPException(status_code=422, detail="Finding source file is unavailable")
    with _PATCH_PREVIEW_LOCK:
        approved_preview = _PATCH_PREVIEWS.get((request.target_id, finding.id))
    if approved_preview != request.patch:
        raise HTTPException(status_code=409, detail="Patch does not match the current generated preview")
    try:
        apply_unified_diff(request.patch, source_path, finding.file)
    except PatchGenerationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    with _PATCH_PREVIEW_LOCK:
        _PATCH_PREVIEWS.pop((request.target_id, finding.id), None)
    clear_target_verifications(request.target_id)
    clear_graph_snapshot_cache(request.target_id)
    return {"finding_id": finding.id, "target_id": request.target_id, "file": finding.file, "applied": True}


@app.get("/api/export/sarif")
def export_sarif(
    target_id: TargetId,
    fail_on_confirmed_high: bool = False,
) -> JSONResponse:
    findings = get_graph_snapshot(target_id).findings
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    has_confirmed_high = False
    level_by_severity = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    for finding in findings:
        rule_id = finding.rule_id or finding.cwe_id
        rules.setdefault(rule_id, {"id": rule_id, "name": finding.sink_type or finding.cwe_id})
        properties = {
            "targetId": finding.target_id,
            "label": finding.label,
            "confidence": finding.confidence,
            "cwe": finding.cwe_id,
            "mergedFrom": finding.merged_from,
            "reason": finding.reason,
        }
        result: dict[str, object] = {
            "ruleId": rule_id,
            "level": level_by_severity.get(finding.severity.upper(), "warning"),
            "message": {"text": f"{finding.cwe_id}: {finding.sink_type or finding.rule_id or 'security finding'} ({finding.label or 'Unclassified'})"},
            "properties": properties,
        }
        if finding.file:
            location: dict[str, object] = {"artifactLocation": {"uri": finding.file}}
            if finding.line:
                location["region"] = {"startLine": finding.line}
            result["locations"] = [{"physicalLocation": location}]
        if finding.evidence:
            result["message"] = {"text": str(result["message"]["text"]), "markdown": finding.evidence}
        results.append(result)
        has_confirmed_high |= finding.label == "Confirmed" and finding.severity.upper() in {"HIGH", "CRITICAL"}
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Mitigata", "rules": list(rules.values())}}, "properties": {"targetId": target_id}, "results": results}],
    }
    status = 409 if fail_on_confirmed_high and has_confirmed_high else 200
    return JSONResponse(sarif, status_code=status, headers={"Content-Disposition": f'attachment; filename="mitigata-{target_id}.sarif"'})


@app.get("/api/planner")
def get_planner(target_id: TargetId) -> dict[str, object]:
    snapshot = get_graph_snapshot(target_id)
    profile = _profile_data(target_id)
    routes, _ = _routes_and_stats(target_id, profile)
    try:
        target_url = load_target_profile(target_id).origin
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise HTTPException(
            status_code=500, detail="Target profile has an invalid target URL"
        ) from exc
    source_root = _source_dir(profile.get("source_dir"))
    plan = build_scan_plan(
        target_id,
        target_url,
        list(snapshot.findings),
        routes,
        model_mode=os.getenv("GRAPHCODEBERT_MODE", "ON"),
        source_revision=str(profile.get("target_revision") or "unknown"),
        source_root=source_root,
    )
    return plan.to_dict()


@app.post("/api/scans", status_code=202)
def start_scan(request: ScanStartRequest) -> dict[str, object]:
    try:
        return scan_jobs.start(request.target_id, request.scan_type)
    except ScanAlreadyRunning as exc:
        raise HTTPException(
            status_code=409,
            detail={"message": str(exc), "active_job": exc.job},
        ) from exc


@app.get("/api/scans/latest")
def get_latest_scan(target_id: TargetId) -> dict[str, object] | None:
    job = scan_jobs.latest(target_id)
    if job and job["status"] in {"COMPLETED", "INCOMPLETE", "FAILED"}:
        clear_graph_snapshot_cache(target_id)
    return job


@app.get("/api/scans/compare")
def compare_scans(target_id: TargetId) -> dict[str, object]:
    return compare_finding_snapshots(scan_jobs.project_root / "data", target_id)


@app.get("/api/scans/{job_id}")
def get_scan(job_id: str) -> dict[str, object]:
    job = scan_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job["status"] in {"COMPLETED", "INCOMPLETE", "FAILED"}:
        clear_graph_snapshot_cache(job["target_id"])
    return job


def _sse_event(payload: dict[str, object], event: str | None = None) -> str:
    prefix = f"event: {event}\n" if event else ""
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return f"{prefix}data: {data}\n\n"


def _verification_candidates(
    finding: UnifiedFinding, target_id: TargetId
) -> list[tuple[UnifiedFinding, str]]:
    """Build bounded probes from AST routes and the request inputs they read."""
    if (
        not finding.sink_type
        or finding.sink_type not in CANARY_PAYLOADS
        or finding.sink_type in NON_PROBEABLE_SINKS
    ):
        return []
    profile = _profile_data(target_id)
    routes, _ = _routes_and_stats(target_id, profile)
    candidates: list[tuple[UnifiedFinding, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for route in routes:
        if (
            route.target_id != target_id
            or not route.resolved
            or not route.contains_location(finding.file, finding.line)
        ):
            continue
        methods = sorted(
            method.upper()
            for method in route.methods
            if method.upper() in {"GET", "POST"}
        )
        for method in methods:
            for request_input in route.input_parameters:
                if request_input.source in {"form", "json"} and method != "POST":
                    continue
                identity = (
                    route.normalized_url,
                    method,
                    request_input.name,
                    request_input.source,
                )
                if identity in seen:
                    continue
                seen.add(identity)
                candidate = finding.model_copy(
                    update={
                        "url": route.raw_url,
                        "method": method,
                        "parameter": request_input.name,
                        "parameter_source": request_input.source,
                        "label": "Code only",
                    }
                )
                candidates.append((candidate, route.normalized_url))
                if len(candidates) >= 4:
                    return candidates
    if (
        len(candidates) < 4
        and finding.sink_type == "ssti"
        and _is_flask_not_found_handler(finding, profile)
    ):
        candidate = finding.model_copy(
            update={
                "url": "/__mitigata_not_found__/{probe_path}",
                "method": "GET",
                "parameter": "probe_path",
                "parameter_source": "path",
                "label": "Code only",
            }
        )
        candidates.append((candidate, "/__mitigata_not_found__/{probe_path}"))
    return candidates


def _is_flask_not_found_handler(
    finding: UnifiedFinding, profile: dict[str, object]
) -> bool:
    """Recognize source within a Flask 404 handler, which has no route decorator."""
    if not finding.file or not finding.line or profile.get("framework") != "flask":
        return False
    source_root = _source_dir(profile.get("source_dir"))
    if source_root is None:
        return False
    source_path = (source_root / finding.file).resolve()
    if not source_path.is_relative_to(source_root) or not source_path.is_file():
        return False
    try:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        return False
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not (node.lineno <= finding.line <= getattr(node, "end_lineno", node.lineno)):
            continue
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "errorhandler"
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
                and decorator.args[0].value == 404
            ):
                return True
    return False


@app.get("/api/verify/{finding_id}/stream")
async def verify_stream(
    finding_id: str, target_id: TargetId
) -> StreamingResponse:
    snapshot = get_graph_snapshot(target_id)
    finding = next(
        (candidate for candidate in snapshot.findings if candidate.id == finding_id),
        None,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found for target")
    if finding.source != "sast":
        raise HTTPException(
            status_code=422, detail="Only source-code findings can be verified"
        )
    candidates = _verification_candidates(finding, target_id)
    if not candidates:
        async def unavailable() -> AsyncIterator[str]:
            yield _sse_event(
                {
                    "finding_id": finding.id,
                    "target_id": target_id,
                    "done": True,
                    "error": (
                        "No safe probe is available for this sink, or no resolved "
                        "route with request inputs was found."
                    ),
                },
                event="verification-error",
            )

        return StreamingResponse(
            unavailable(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )
    clear_verification_result(target_id, finding.id)
    clear_graph_snapshot_cache(target_id)

    async def stream() -> AsyncIterator[str]:
        current_label = finding.label or "Code only"
        yield _sse_event(
            {
                "finding_id": finding.id,
                "target_id": target_id,
                "label": current_label,
                "probe_history": [],
                "done": False,
            }
        )
        final_state: dict[str, object] = {
            "label": "Code only",
            "probe_history": [],
            "evidence": None,
            "http_status": None,
        }
        combined_history: list[dict[str, object]] = []
        successful_candidate: tuple[UnifiedFinding, str] | None = None
        try:
            for candidate_finding, route_path in candidates:
                initial_state = state_from_finding(candidate_finding)
                candidate_history: list[dict[str, object]] = []
                async for state in iter_verification_states(initial_state):
                    final_state = state
                    current_label = state["label"]
                    candidate_history = [
                        {
                            **record,
                            "route": route_path,
                            "parameter": candidate_finding.parameter,
                            "parameter_source": candidate_finding.parameter_source,
                        }
                        for record in state["probe_history"]
                    ]
                    payload: dict[str, object] = {
                        "finding_id": finding.id,
                        "target_id": target_id,
                        "label": current_label,
                        "probe_history": [*combined_history, *candidate_history],
                        "done": False,
                    }
                    if state.get("evidence"):
                        payload["evidence"] = state["evidence"]
                    yield _sse_event(payload)
                    await asyncio.sleep(0)
                combined_history = [*combined_history, *candidate_history]
                if final_state.get("label") == "Confirmed":
                    successful_candidate = (candidate_finding, route_path)
                    break

            current_label = (
                "Confirmed" if successful_candidate is not None else "Code only"
            )
            evidence = final_state.get("evidence")
            if successful_candidate is not None:
                candidate_finding, route_path = successful_candidate
                save_confirmed_result(
                    target_id,
                    finding.id,
                    {
                        "label": "Confirmed",
                        "url": candidate_finding.url,
                        "route": route_path,
                        "method": candidate_finding.method,
                        "parameter": candidate_finding.parameter,
                        "parameter_source": candidate_finding.parameter_source,
                        "evidence": evidence,
                        "http_status": final_state.get("http_status"),
                        "probe_history": combined_history[-8:],
                    },
                )
                clear_graph_snapshot_cache(target_id)
            yield _sse_event(
                {
                    "finding_id": finding.id,
                    "target_id": target_id,
                    "label": current_label,
                    "probe_history": combined_history,
                    "evidence": evidence,
                    "done": True,
                }
            )
        except Exception:
            logger.exception(
                "Verification stream failed for target %s finding %s",
                target_id,
                finding_id,
            )
            yield _sse_event(
                {
                    "finding_id": finding.id,
                    "target_id": target_id,
                    "done": True,
                    "error": "Verification failed; check the engine logs.",
                },
                event="verification-error",
            )

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
