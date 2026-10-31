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
