from __future__ import annotations

from collections.abc import AsyncIterator

from ..ingestion.schema import UnifiedFinding
from .nodes import (
    probe_generator,
    response_evaluator,
    retry_evaluator,
    runtime_executor,
    should_retry,
)
from .state import AlertState, state_from_finding


async def iter_verification_states(
    initial_state: AlertState,
) -> AsyncIterator[AlertState]:
    """Run the bounded probe/evaluate/retry sequence and yield each state."""
    state = initial_state
    while True:
        state = probe_generator(state)
        yield state

        state = await runtime_executor(state)
        yield state

        state = response_evaluator(state)
        yield state

        if should_retry(state) == "end":
            return
        state = retry_evaluator(state)
        yield state


async def verify_finding(finding: UnifiedFinding) -> AlertState:
    """Run bounded verification for a SAST finding with request metadata."""
    result = state_from_finding(finding)
    async for result in iter_verification_states(result):
        pass
    return result
