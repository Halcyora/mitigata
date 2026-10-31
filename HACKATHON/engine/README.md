# Engine package

This package holds the planned SAST/DAST correlation engine for Problem 06.

The monorepo is intentionally split into language-independent engine logic and
per-target adapters so that Flask and Juice Shop can share the same ingestion,
correlation, classification, and API layers while selecting an adapter per target
profile.

## Directory map

- `adapters/` route extraction adapters and framework-specific discovery logic
- `ingestion/` normalization of Semgrep and ZAP raw output into `UnifiedFinding`
- `ast_mapper/` sink detection, call-graph reachability, and route normalization
- `langgraph_loop/` runtime verification and evidence-gathering workflow
- `classifier/` triage into Confirmed / Code only / Runtime only
- `patch_engine/` patch generation and fallback strategy
- `compliance/` scoring and policy mappings
- `api/` API endpoints for scans and verification

## Phase 3 route mapping

`engine.ast_mapper.call_graph.build_call_graph(TargetProfile(...))` runs the
shared three-pass mapper. Select Python/Flask or JavaScript/Express from the
profile; both return the same `RouteNode`, `CodeScope`, and `ParameterRead`
models. Scope file paths are target-relative.

The mapper resolves only direct local/imported callees and only statically
named request keys. Dynamic route mounts are retained as unresolved records and
cannot match DAST traffic. Sink coverage is reported per target in `stats`,
including the measured `suppression_ratio`; ratios are not shared across target
profiles. `enrich_findings_with_ast` attaches reachability to SAST findings, and
`correlate_and_merge` confirms a pair only when target, CWE, route, HTTP method,
source location, and the named parameter/source all agree.
