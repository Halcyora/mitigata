from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from ..ingestion.schema import UnifiedFinding
from ..langgraph_loop.graph import verification_graph
from ..langgraph_loop.state import state_from_finding
from .graph import GraphResponse, get_graph_snapshot

logger = logging.getLogger(__name__)

TargetId = Literal["flask_demo", "juice_shop"]

app = FastAPI(title="Mitigata correlation engine")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_methods=["GET"],
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
