# LangGraph — PS5 Verification Loop Reference

**Repository:** [langchain-ai/langgraph](https://github.com/langchain-ai/langgraph)  
**Category:** 04-Orchestration  
**PS5 Role:** Core orchestration engine for the **LangGraph Verification Loop** (PS5 §3.3)  
**Status:** Required for PS5 prototype

---

## Why LangGraph for PS5

PS5 requires a **stateful agent** that takes an unverified SAST sink, fires a targeted HTTP probe at the sandboxed Docker container, evaluates the response, and transitions the alert through defined states. LangGraph's graph-based state machine maps directly onto this workflow:

- **Nodes** = processing steps (probe generator, runtime executor, response evaluator)
- **Edges** = conditional transitions (evidence found → T1, blocked → T2)
- **State** = the alert object carrying sink metadata, probe payload, HTTP response, and tier classification
- **Persistence** = durable execution across the probe lifecycle without losing context

---

## PS5 State Machine Design

```
[UNVERIFIED_SINK]
      │
      ▼
[probe_generator]    ── Craft safe canary HTTP request for the flagged route + parameter
      │
      ▼
[runtime_executor]   ── Fire probe at Docker sandbox (timeout: 2s, local network only)
      │
      ▼
[response_evaluator] ── Analyse HTTP response / stack trace for exploitation evidence
      │
      ├─► evidence_found=True  ──► [CONFIRMED_EXPLOITABLE]  (T1 🔴)
      ├─► blocked/inconclusive ──► [REACHABLE_UNVERIFIED]   (T2 🟠)
      └─► no_route_found       ──► [UNREACHABLE_CODE]        (T3 🟡)
```

---

## Key LangGraph Concepts for PS5

| Concept | PS5 Usage |
| --- | --- |
| `StateGraph` | Define the verification loop graph with typed state |
| `TypedDict` state | Carry `sink_id`, `route`, `probe_payload`, `http_response`, `tier`, `evidence` |
| `add_node` | Register `probe_generator`, `runtime_executor`, `response_evaluator` |
| `add_conditional_edges` | Route from `response_evaluator` to T1/T2/T3 based on evidence |
| `compile()` | Produce the runnable graph |
| `stream()` / `invoke()` | Run the loop and stream state updates to the UI in real time |
| `MemorySaver` | Persist state across re-verification runs (patch → re-probe flow) |

---

## Minimal Implementation Skeleton

```python
from langgraph.graph import StateGraph, END
from typing import TypedDict, Literal

class AlertState(TypedDict):
    sink_id: str
    route: str
    method: str
    parameter: str
    probe_payload: str
    http_response: dict
    evidence: str
    tier: Literal["T1", "T2", "T3", "T4", "UNVERIFIED"]

def probe_generator(state: AlertState) -> AlertState:
    # Craft safe canary payload for the route/parameter
    ...

def runtime_executor(state: AlertState) -> AlertState:
    # Fire HTTP probe at Docker sandbox, capture response
    ...

def response_evaluator(state: AlertState) -> AlertState:
    # Analyse response for exploitation evidence
    ...

def route_result(state: AlertState) -> str:
    if state["evidence"]:
        return "confirmed"
    return "unverified"

graph = StateGraph(AlertState)
graph.add_node("probe_generator", probe_generator)
graph.add_node("runtime_executor", runtime_executor)
graph.add_node("response_evaluator", response_evaluator)

graph.set_entry_point("probe_generator")
graph.add_edge("probe_generator", "runtime_executor")
graph.add_edge("runtime_executor", "response_evaluator")
graph.add_conditional_edges(
    "response_evaluator",
    route_result,
    {"confirmed": END, "unverified": END}
)

app = graph.compile()
```

---

## Safety Constraints (from PS5 §3.3 + §4)

- All probes must use **read-only canary strings** — no `DROP TABLE`, no OS commands
- Probes must target only routes **already flagged by SAST** — no spider/crawl
- Each probe must complete in **< 2 seconds** — set `httpx` timeout accordingly
- All network calls must be restricted to the **local Docker network** — no external traffic
- The LangGraph state must record the full HTTP request + response as evidence

---

## Evaluation Record

| Question | Finding |
| --- | --- |
| Intended use case | PS5 §3.3 stateful verification loop — probe → evaluate → classify |
| License | MIT — confirmed suitable for prototype |
| Runtime prerequisites | Python 3.11+, `langgraph>=0.2`, `langchain-core` |
| Model/provider dependency | Optional — nodes can be pure Python without LLM calls |
| Isolation | All execution within local Docker network; no external API calls in probe nodes |
| Test scenario | Fire canary SQLi probe at `/login` route; verify T1 classification on error response |
| PS5 adoption decision | **Adopted** — required by problem statement |
