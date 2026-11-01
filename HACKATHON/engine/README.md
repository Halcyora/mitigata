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
- `verification/` bounded runtime probes and evidence-gathering workflow
- `classifier/` classification and finding priority helpers
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
`correlate_and_merge` labels a pair `Confirmed` when target, canonical CWE
number, route, HTTP method, source location, and named parameter/source all
agree. CWE formatting is normalized (for example, `CWE-079` and `CWE-79`), but
different CWE numbers are never treated as equivalent. If target, CWE, route,
and source location agree but request-input evidence is incomplete, the pair is
`Corroborated` at lower confidence. A missing HTTP method is treated as unknown;
an explicitly mismatched method, parameter, or source prevents correlation.
Header parameter names are compared case-insensitively; other request parameter
names remain case-sensitive.

Before correlation, `engine.ingestion.deduplication.deduplicate_findings`
collapses repeated SAST reports by target/CWE/source location and DAST reports
by target/CWE/rule/request surface. ZAP CORS and CSP policy alerts are
target-wide, so repeated observations across routes and methods collapse into
one issue while retaining source alert IDs in `merged_from`, observed route
templates in `routes`, and combined evidence in `evidence_items`. DAST payload,
status, parameter, alert ID, URL, method, and evidence are retained per alert.
Incremental DAST
ingestion uses the same identity rules. Distinct rules at different source
locations and distinct endpoint-specific alerts remain separate. The dashboard
shows each retained alert evidence record and merged source IDs in the finding
details.

## Phase 4 runtime verification

`await engine.verification.verify_finding(finding)` runs one bounded Python
verification workflow for an unverified SAST `UnifiedFinding`. The API derives
up to four route/method/request-input candidates from resolved AST scopes. Each
candidate uses a configured `target_id`, route, HTTP method, sink type,
parameter, and parameter source. Target origins are loaded from
`configs/<target_id>.yaml`; finding URLs never select the request host. Only
loopback and configured Docker target service names are accepted, redirects and
environment proxies are disabled, the response preview is capped at 500 bytes,
and each request has a two-second wall-clock deadline. Only GET, HEAD, OPTIONS,
and POST are eligible; other methods end as `UNVERIFIED` without making a
request.

The workflow chooses a sink-specific canary, records each attempt in
`probe_history`, evaluates bounded response evidence, and retries once when the
first attempt is inconclusive or transiently fails. The open-redirect probe
checks an external canary `Location` header without following it. Sinks without
a safe, specific runtime signal remain unverified. A positive probe result
is stored per target in `data/raw/<target>-verification.json`, merged into the
graph response as `Confirmed`, and cleared when a new SAST baseline completes
or a patch is applied. Failed or inconclusive probes do not change the saved
finding label. SAST/DAST correlation remains separately gated by target, CWE,
route, and source scope; a route-only match is not corroboration.

## Finding labels and prioritization

`engine.classifier.classify(ast_reachable, verification_label, is_config_only,
dual_confirmed=False)` implements the build-plan priority rules and returns an
immutable `ClassificationResult` with a `Label`, confidence, and explanation.
Runtime `Confirmed` wins first (0.98 when independently dual-confirmed by CWE
and route, otherwise 0.90); configuration-only issues become `Runtime only`
(0.85); unreachable, reachable-but-inconclusive, and unknown-reachability
findings become `Code only` (0.95, 0.70, and 0.50 respectively). Unverified or
inconclusive probe labels do not imply runtime confirmation.

Use `apply_classification` to create a copy of a `UnifiedFinding` with the
resulting label and confidence, and `sort_findings` to keep findings in
Confirmed, Corroborated, Code only, Runtime only priority order, then rank
within each group by a displayed 0–100 score derived from severity,
reachability, runtime proof, request inputs, and evidence.
The helper does not mutate finding evidence or infer config-only/dual-confirmed
status; callers must supply that evidence explicitly.

## Phase 6 patch suggestions

`engine.patch_engine.generate_patch(sink_type, file_path, line, code_context,
cwe_id=...)` tries Sarvam Token Factory when `SARVAM_API_KEY` is configured.
The prompt contains the normalized sink type and CWE, repository-relative file
path, reported line, and up to 81 numbered source lines around that location
(capped at 16,000 characters). It does not include the target ID, scanner report,
runtime evidence, or DAST payload. Source code in the excerpt may contain
embedded credentials; review the target source and Sarvam data-handling
requirements before enabling patch generation for it. The API uses
`SARVAM_BASE_URL` (default `https://api.sarvam.ai/v2`) and `SARVAM_MODEL`
(default `glm5.3`). Source context is sent to Sarvam, so configure it only for
code that is approved for that service. Requests use a 10-second timeout and no
SDK retries. Add your Sarvam key to `HACKATHON/.env`; never commit it.
Run `python scripts/check_sarvam.py` from `HACKATHON/` to verify the configured
key and model with a minimal chat completion.

Only a bounded single-file unified diff with valid hunk counts and exact
repository-relative `a/` and `b/` paths is returned as an LLM patch. Malformed,
empty, or out-of-scope model output is rejected; API errors and invalid model
output are logged before falling back to CWE-mapped sink templates or generic,
non-applicable remediation guidance. If no valid LLM patch is available, a
deterministic sink template is returned for supported vulnerability types.
`PatchResult.kind` distinguishes a diff from a remediation snippet; neither is
applied automatically. Callers must review a result in the context of the
specific project and test it before applying. Generic guidance is never offered
as an applicable code diff.

## Phase 7 graph API and dashboard

`GET /api/planner` returns a plan preview; it does not start a scan. The
dashboard has separate **Run SAST** and **Run targeted + broad DAST** actions.
Both call `POST /api/scans` with the selected target and `scan_type`. SAST
produces the Semgrep report; DAST reuses that report, builds a route plan, and
executes targeted ZAP tasks before broad fallback tasks while the configured
DAST budget remains. `GET /api/scans/latest?target_id=...` exposes the live
phase and final task counts. A finished job invalidates the graph cache so the
dashboard reloads findings. Only one scan may run at a time.

`GET /api/graph?target_id=flask_demo` (or `juice_shop`) parses that profile's
Semgrep/ZAP reports, maps its routes, correlates findings, and returns graph
nodes, edges, and target-local statistics. Findings are sorted with Confirmed
first and receive stable IDs so the UI can safely use them for detail selection
and verification. API nodes include seed coordinates; the dashboard computes
the final hierarchical layout with ELK. Graph snapshots are cached for ten
seconds.

`GET /api/verify/{finding_id}/stream?target_id=...` starts the existing bounded
runtime verification for that target's Code only finding and streams label,
probe-history, and final status updates as SSE. The finding must belong to the
selected target; runtime-only findings cannot be submitted for code verification.
Verification continues to use the configured local target origin and the
existing safe probe constraints. The issue detail panel exposes this action and
renders the bounded probe history and outcome.

`GET /api/scans/compare?target_id=...` compares the latest completed scan with
the previous completed scan of the same type. It reports new, fixed, and still
open issues using target-scoped CWE and location/request-surface identities.
Only issue metadata is retained in `data/raw/<target>-finding-history.json`.
The SARIF export accepts `fail_on_confirmed_high=true`; it returns HTTP 409
when a confirmed High or Critical issue exists, which can be used as a CI gate.

The React dashboard in `frontend/` uses TanStack Query for target-keyed data,
React Flow for graph interaction, and ELK layered layout. Its detail panel
shows finding location, evidence, confidence, and live probe history.
