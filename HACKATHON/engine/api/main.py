from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from collections.abc import AsyncIterator
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from ..compliance.mapping import FRAMEWORK_ORDER, map_finding_to_frameworks
from ..compliance.risk_calculator import calculate_inr_exposure
from ..ingestion.schema import UnifiedFinding
from ..langgraph_loop.graph import verification_graph
from ..langgraph_loop.state import state_from_finding
from ..patch_engine.llm_patcher import (
    PatchGenerationError,
    apply_unified_diff,
    generate_patch,
)
from ..dast_planner.planner import build_scan_plan
from .graph import (
    GraphResponse,
    _profile_data,
    _routes_and_stats,
    _source_dir,
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
        result = generate_patch(finding.sink_type, finding.file, finding.line, context)
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
    target_url = profile.get("target_url")
    source_root = _source_dir(profile.get("source_dir"))
    if not isinstance(target_url, str):
        raise HTTPException(status_code=500, detail="Target profile has no target URL")
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


def _sse_event(payload: dict[str, object], event: str | None = None) -> str:
    prefix = f"event: {event}\n" if event else ""
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return f"{prefix}data: {data}\n\n"


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
    try:
        initial_state = state_from_finding(finding)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

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
        final_state = initial_state
        try:
            async for state in verification_graph.astream(
                initial_state, stream_mode="values"
            ):
                final_state = state
                current_label = state["label"]
                payload: dict[str, object] = {
                    "finding_id": finding.id,
                    "target_id": target_id,
                    "label": current_label,
                    "probe_history": state["probe_history"],
                    "done": False,
                }
                if state.get("evidence"):
                    payload["evidence"] = state["evidence"]
                if state.get("error"):
                    payload["error"] = state["error"]
                yield _sse_event(payload)
                await asyncio.sleep(0)
            yield _sse_event(
                {
                    "finding_id": finding.id,
                    "target_id": target_id,
                    "label": current_label,
                    "probe_history": final_state["probe_history"],
                    "evidence": final_state.get("evidence"),
                    "error": final_state.get("error"),
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
