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

## Phase 4 runtime verification

`await engine.langgraph_loop.verify_finding(finding)` runs one bounded LangGraph
verification workflow for an unverified SAST `UnifiedFinding`. The finding must
include a configured `target_id`, route, HTTP method, sink type, parameter, and
parameter source. Target origins are loaded from `configs/<target_id>.yaml`;
finding URLs never select the request host. Only loopback and the configured
Docker target service names are accepted, redirects and environment proxies are
disabled, the response preview is capped at 500 bytes, and each request has a
two-second wall-clock deadline. Only GET, HEAD, OPTIONS, and POST are eligible;
other methods end as `UNVERIFIED` without making a request.

The graph chooses a benign, sink-specific canary, records each attempt in
`probe_history`, evaluates bounded response evidence, and retries once when the
first attempt is inconclusive or transiently fails. Unsupported sinks and
unsafe/incomplete request metadata are reported as `UNVERIFIED`. The result
keeps verification state separate from persisted finding classification;
callers should update a finding only from the returned label/evidence.

## Phase 5 three-label classification

`engine.classifier.classify(ast_reachable, langgraph_label, is_config_only,
dual_confirmed=False)` implements the build-plan priority rules and returns an
immutable `ClassificationResult` with a `Label`, confidence, and explanation.
LangGraph `Confirmed` wins first (0.98 when independently dual-confirmed by CWE
and route, otherwise 0.90); configuration-only issues become `Runtime only`
(0.85); unreachable, reachable-but-inconclusive, and unknown-reachability
findings become `Code only` (0.95, 0.70, and 0.50 respectively). Unverified or
inconclusive probe labels do not imply runtime confirmation.

Use `apply_classification` to create a copy of a `UnifiedFinding` with the
resulting label and confidence, and `sort_findings` to keep findings in
Confirmed, Code only, Runtime only priority order while preserving tie order.
The helper does not mutate finding evidence or infer config-only/dual-confirmed
status; callers must supply that evidence explicitly.

## Phase 6 patch suggestions

`engine.patch_engine.generate_patch(sink_type, file_path, line, code_context)`
tries Azure OpenAI first when `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_KEY` are
configured. It uses `AZURE_OPENAI_DEPLOYMENT` (default `gpt-4o`) and then
`AZURE_OPENAI_FALLBACK_DEPLOYMENT` (default `gpt-4o-mini`). Source context is sent
to that configured Azure endpoint, so configure it only for code that is
approved for that service. Requests use a 10-second timeout and no SDK retries.

Only a bounded single-file unified diff with valid hunk counts and exact
repository-relative `a/` and `b/` paths is returned as an LLM patch. Malformed,
empty, or out-of-scope model output is rejected; API errors and invalid model
output are logged before trying the fallback deployment. If no valid LLM patch
is available, a deterministic sink template is returned for SQL injection,
XSS, command injection, weak password hashes, JWT verification, or SSTI.
`PatchResult.kind` distinguishes a diff from a remediation snippet; neither is
applied automatically. Callers must review a result in the context of the
specific project and test it before applying. Unsupported sinks without an
available LLM patch raise `PatchGenerationError`.
