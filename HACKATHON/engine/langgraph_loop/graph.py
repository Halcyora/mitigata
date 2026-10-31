from __future__ import annotations

from langgraph.graph import END, StateGraph

from ..ingestion.schema import UnifiedFinding
from .nodes import (
    probe_generator,
    response_evaluator,
    retry_evaluator,
    runtime_executor,
    should_retry,
)
from .state import AlertState, state_from_finding


def build_verification_graph():
    graph = StateGraph(AlertState)
    graph.add_node("probe_generator", probe_generator)
    graph.add_node("runtime_executor", runtime_executor)
    graph.add_node("response_evaluator", response_evaluator)
    graph.add_node("retry_evaluator", retry_evaluator)

    graph.set_entry_point("probe_generator")
    graph.add_edge("probe_generator", "runtime_executor")
    graph.add_edge("runtime_executor", "response_evaluator")
    graph.add_conditional_edges(
        "response_evaluator",
        should_retry,
        {"retry": "retry_evaluator", "end": END},
    )
    graph.add_edge("retry_evaluator", "probe_generator")
    return graph.compile()


verification_graph = build_verification_graph()


async def verify_finding(finding: UnifiedFinding) -> AlertState:
    """Run bounded verification for a SAST finding with route/input metadata."""
    state = state_from_finding(finding)
    result = await verification_graph.ainvoke(state)
    return result
