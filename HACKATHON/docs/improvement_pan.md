# P06 Architecture Improvement Plan

## Semgrep-Guided, GraphCodeBERT-Assisted, Route-Aware, Time-Budgeted DAST

**Status:** Deterministic route planning and bounded ZAP orchestration implemented; remaining phases proposed\
**Applies to:** P06 SAST & DAST Correlation Engine\
**Baseline:** `P06-Architecture.md` (Architecture v1.3)\
**Primary change:** Replace the current broad-first DAST execution
strategy with a prioritized, feedback-driven scan plan. Add an optional
GraphCodeBERT-based code-context layer to help rank ambiguous route/finding
candidates without replacing deterministic analysis or runtime verification.

**Implementation note:** `scripts/run_scan.py --dast` now maps normalized
Semgrep findings to the existing AST route inventory, runs supported
CWE-specific ZAP checks before route-wide coverage, and records task outcomes
and budget cutoffs under `data/raw/`. The initial verified rule map is limited
to CWE-22, CWE-78, CWE-79, CWE-89, and CWE-601. GraphCodeBERT, incremental
correlation/UI events, and the controlled benchmark remain proposed work.

------------------------------------------------------------------------

## 1. Executive Summary

The current architecture already has several important foundations:

-   Semgrep findings are normalized into `UnifiedFinding` records.
-   The AST route mapper extracts routes, handler scopes, helper scopes,
    and request parameter reads.
-   The correlation engine uses strict evidence matching rather than
    CWE-only or route-only matching.
-   ZAP findings are normalized and correlated with SAST findings.
-   Findings are classified as `Confirmed`, `Code only`, or
    `Runtime only`.
-   Target containers are isolated on the internal Docker network.

The proposed improvement adds a planning stage before ZAP execution.
Instead of asking ZAP to perform broad coverage first and correlating
after the scan, the engine will use static analysis and route metadata
to decide which routes and ZAP rules should be tested first. An optional
GraphCodeBERT layer can enrich the planner's context when multiple routes,
helpers, or code locations are plausible candidates. It is a ranking aid,
not a new source of authoritative security evidence.

### The core workflow

1.  AST extracts all Flask routes and their parameters.
2.  Semgrep identifies suspicious source-code locations.
3.  The planner maps those locations to routes.
4.  The planner selects relevant ZAP rules for each mapped route.
5.  ZAP tests the selected routes first.
6.  Remaining time is used for broader coverage.
7.  The correlation engine processes results incrementally.

The optional GraphCodeBERT enrichment sits between steps 3 and 4: it may
rank already-mapped candidate contexts before the planner selects tasks.
It does not change the seven core workflow stages.

### Central design principle

**Targeted DAST does not make an individual ZAP vulnerability test
inherently faster. It reduces the number of unnecessary tests ZAP needs
to perform before useful results are available.**

The performance gain comes from better test selection and ordering, not
from claiming that ZAP's underlying vulnerability checks execute faster.

**Model boundary:** GraphCodeBERT does not make a route reachable, prove
a taint path, or confirm a vulnerability. It may rank candidate contexts
that AST and static analysis have already identified.

------------------------------------------------------------------------

## 2. Goals and Non-Goals

### Goals

1.  Prioritize routes with static-analysis evidence of likely
    vulnerabilities.
2.  Prioritize ZAP rules that are relevant to the Semgrep finding and
    route input surface.
3.  Begin useful runtime testing earlier in the scan.
4.  Preserve broad DAST coverage by using remaining scan time for a
    fallback coverage phase.
5.  Feed ZAP alerts into correlation as they arrive, rather than waiting
    for the entire scan to finish.
6.  Preserve strict correlation requirements and target isolation from
    architecture v1.3.
7.  Make prioritization explainable and auditable.
8.  Evaluate an optional GraphCodeBERT code-context layer for ranking
    ambiguous route/finding candidates and improving test ordering.
9.  Keep model inference bounded, cacheable, locally executable, and
    non-blocking for the scan pipeline.

### Non-goals

-   Do not claim that a targeted ZAP rule runs faster than the same rule
    in a broad scan.
-   Do not replace Semgrep with ZAP, or ZAP with a custom vulnerability
    scanner.
-   Do not treat a Semgrep finding as proof of runtime exploitability.
-   Do not weaken the existing strict SAST--DAST correlation gate.
-   Do not remove the broad-coverage phase.
-   Do not run active tests against targets outside the selected,
    authorized local target profile.
-   Do not use GraphCodeBERT as a standalone vulnerability detector,
    taint analyzer, exploitability oracle, or replacement for Semgrep.
-   Do not allow a model score to create a route mapping, suppress a
    Semgrep finding, authorize a scan, select an unsupported ZAP rule,
    or satisfy the strict `Confirmed` correlation gate.
-   Do not make model availability a prerequisite for starting a scan.

------------------------------------------------------------------------

## 3. Proposed Architecture

### 3.1 High-level flow

``` mermaid
flowchart TD
    SRC["Read-only Flask source"] --> AST["Flask AST route extractor"]
    SRC --> SEM["Semgrep SAST scan"]
    AST --> ROUTES["Route inventory<br/>URL + method + handler + scopes + parameters"]
    SEM --> FINDINGS["Normalized Semgrep findings<br/>CWE + file + line + rule + sink"]
    ROUTES --> MAP["Deterministic route/finding candidate mapping"]
    FINDINGS --> MAP
    MAP --> INTEL["Optional GraphCodeBERT context enrichment"]
    MAP --> PLAN["DAST planner"]
    INTEL -. "rank-only signal; never authoritative" .-> PLAN
    PLAN --> PRIORITY["Route and rule priority queue"]
    PRIORITY --> TARGET["Phase 1: targeted ZAP tests"]
    TARGET --> EVENTS["Incremental ZAP alert/event stream"]
    EVENTS --> CORR["Incremental correlation engine"]
    ROUTES --> CORR
    FINDINGS --> CORR
    CORR --> CLASSIFY["Update finding classification"]
    PRIORITY --> BUDGET{"Time remains?"}
    BUDGET -->|Yes| BROAD["Phase 2: broader ZAP coverage"]
    BUDGET -->|No| STOP["Stop scheduling new tests"]
    BROAD --> EVENTS
    STOP --> FINAL["Finalize scan state and report"]
    CLASSIFY --> FINAL
```

### 3.2 Component responsibilities

  -----------------------------------------------------------------------
  Component               Responsibility          Output
  ----------------------- ----------------------- -----------------------
  Flask AST extractor     Discover route          `RouteNode[]`
                          declarations, methods,  
                          prefixes, handler       
                          scopes, and request     
                          parameter reads         

  Semgrep runner/parser   Identify suspicious     `UnifiedFinding[]`
                          source locations and    
                          normalize findings      

  Route mapper            Associate Semgrep       Route evidence
                          locations with route    
                          scopes and observed     
                          inputs                  

  Code intelligence       Optionally encode       `CodeContextAssessment[]`
                          focused code/data-flow  (advisory only)
                          contexts and rerank
                          candidate relationships

  DAST planner            Rank route/rule         `ScanPlan`
                          combinations using code 
                          evidence and route      
                          metadata                

  ZAP orchestrator        Execute targeted work   ZAP events and alerts
                          first, then broader     
                          coverage within the     
                          remaining budget        

  Incremental correlator  Match each arriving     Updated correlation
                          DAST alert against SAST records
                          and route evidence      

  Classifier              Recalculate labels and  `Confirmed`,
                          confidence as evidence  `Code only`,
                          changes                 `Runtime only`

  Scan coordinator        Own deadlines,          Scan state
                          cancellation, progress, 
                          and finalization        
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 4. Stage 1 --- Flask AST Route and Parameter Extraction

The route inventory is produced before the planner schedules DAST work.

### 4.1 Route information to extract

For each Flask route, collect:

-   `target_id`
-   normalized URL and original route path
-   HTTP methods
-   Blueprint and resolved `url_prefix`
-   handler module, function, and source location
-   handler code scope
-   directly called local helper scopes, retaining the existing one-hop
    limitation unless deliberately expanded later
-   statically identifiable request parameter reads
-   parameter source: path, query, form, JSON/body, or header
-   unresolved or dynamic route metadata

Example:

``` python
@bp.route("/orders/<int:order_id>", methods=["GET", "POST"])
def get_order(order_id):
    customer = request.args.get("customer")
    ...
```

Illustrative route record:

``` json
{
  "target_id": "flask_demo",
  "normalized_url": "/api/orders/{param}",
  "original_path": "/orders/<int:order_id>",
  "methods": ["GET", "POST"],
  "handler": "get_order",
  "scopes": [
    {
      "file": "app/routes/orders.py",
      "start_line": 10,
      "end_line": 28,
      "function": "get_order"
    }
  ],
  "input_parameters": [
    {"name": "order_id", "source": "path"},
    {"name": "customer", "source": "query"}
  ]
}
```

The example is illustrative; actual route and parameter values must come
from AST analysis.

### 4.2 Extraction constraints

-   Use Python's standard-library `ast` module for Python source
    parsing.
-   Do not execute target application code to discover routes.
-   Resolve statically declared Flask decorators and Blueprint prefixes.
-   Preserve unresolved dynamic registrations explicitly.
-   Keep source paths and line ranges so a finding can be mapped back to
    a route scope.
-   Do not assume that every parameter accepted by a handler is read
    from the HTTP request.
-   Do not infer a parameter name or source when static evidence is
    unavailable.

### 4.3 Output contract

The existing `RouteNode`, `CodeScope`, and `ParameterRead` contracts in
architecture v1.3 should be extended only where required. The planner
should consume these records rather than implement a second route
parser.

------------------------------------------------------------------------

## 5. Stage 2 --- Semgrep Suspicious-Location Extraction

Semgrep remains the SAST source. Its job is to identify suspicious code
locations; it does not decide whether a vulnerability is exploitable at
runtime.

For each finding, retain at least:

-   `finding_id`
-   `target_id`
-   `rule_id`
-   `cwe_id`
-   severity
-   file and line range
-   function or enclosing scope when available
-   sink type or vulnerability category
-   source location and message
-   relevant metavariables or data-flow information when available

Normalize these records into the existing `UnifiedFinding` model.

### 5.1 Route mapping

The planner maps each Semgrep location to the AST route inventory:

1.  Restrict candidate routes to the same `target_id`.
2.  Find route scopes containing the Semgrep file and line.
3.  Use handler and one-hop helper scopes already recorded by the AST
    mapper.
4.  Attach route methods and observed request parameters.
5.  Mark findings with no defensible route mapping as unresolved.

A finding can map to more than one route if the source scope is shared.
Preserve all valid candidates and their evidence; do not arbitrarily
select one route.

### 5.2 Mapping confidence

Use explicit mapping states rather than pretending all mappings are
equally certain:

-   `EXACT_SCOPE`: finding location falls inside a route handler scope.
-   `HELPER_SCOPE`: finding location falls inside a directly called
    helper scope.
-   `MULTIPLE_ROUTE_CANDIDATES`: shared code is reachable from multiple
    routes.
-   `UNRESOLVED`: no supported route mapping.

These states are planner metadata. They must not weaken the correlation
engine's existing strict confirmation requirements.

------------------------------------------------------------------------

## 6. Stage 3 --- DAST Planner and Rule Selection

The planner converts route and Semgrep evidence into an ordered list of
route/rule tasks.

### 6.1 Planning unit

The basic scheduling unit is a **route × HTTP method × ZAP rule/policy**
combination, scoped to one target profile.

A task should include:

``` json
{
  "task_id": "generated-id",
  "target_id": "flask_demo",
  "route_id": "route-id",
  "normalized_url": "/api/orders/{param}",
  "method": "GET",
  "rule_id": "selected-zap-policy-id",
  "reason_codes": [
    "SAST_CWE_MATCH",
    "ROUTE_SCOPE_MATCH",
    "PARAMETER_SURFACE_MATCH"
  ],
  "code_context_assessment_id": null,
  "model_ranking_used": false,
  "priority_score": 0,
  "phase": "TARGETED",
  "status": "QUEUED"
}
```

The `priority_score` above is a placeholder in the schema example, not a
measured score.

### 6.2 Rule relevance

Use a maintained mapping between Semgrep rule/CWE/sink categories and
the ZAP rules or scan policies that can meaningfully test them.

Illustrative mapping:

  -----------------------------------------------------------------------
  Static evidence / input surface     Candidate DAST test family
  ----------------------------------- -----------------------------------
  SQL injection sink / CWE-89         SQL injection checks

  Reflected or stored XSS sink /      XSS checks
  CWE-79                              

  Command execution sink / CWE-78     Command injection checks, if
                                      supported by the configured ZAP
                                      policy

  Path/file access sink / CWE-22      Path traversal checks

  Redirect handling / CWE-601         Open redirect checks

  User-controlled template input      Template injection checks, if a
                                      supported test policy is configured

  No relevant SAST finding            Eligible for broader coverage phase
  -----------------------------------------------------------------------

This table is a planning guide, not a claim that every listed CWE has a
one-to-one built-in ZAP rule. The implementation must validate the
actual rule IDs and capabilities available in the installed ZAP version
and configured add-ons.

### 6.3 Parameter-aware selection

Use AST parameter reads to narrow test inputs:

-   Prefer query-focused checks when the route reads query parameters.
-   Prefer form/body checks when the route reads form or JSON fields.
-   Include path-oriented checks when route path parameters are present
    and relevant.
-   Include header-oriented checks only when the route or finding
    supports that input surface.
-   If the source of an input is unknown, do not fabricate a parameter
    binding; retain the task as lower-confidence or use a broader policy
    where appropriate.

A route can have multiple relevant parameters. The planner should
preserve the parameter name and source in the task metadata where ZAP
can accept that level of targeting. If the ZAP integration cannot target
a parameter directly, record the limitation and target the route/method
with the relevant rule policy instead.

### 6.4 Priority model

Use a transparent, deterministic priority model. A practical initial
ordering is:

1.  Exact route-scope match with a relevant Semgrep sink and matching
    input surface.
2.  Direct-helper-scope match with a relevant sink and matching input
    surface.
3.  Relevant Semgrep finding mapped to a route, but input parameter
    evidence is incomplete.
4.  Multiple candidate routes or ambiguous shared helper mapping.
5.  Routes with no matching Semgrep finding, reserved for broader
    coverage.

Severity can break ties within a priority class. Do not let severity
alone turn an unrelated route/rule combination into a targeted task.

Store the reason codes used for each decision so the UI and logs can
explain why a task was selected.

### 6.5 Planner output

The planner emits a `ScanPlan` containing:

-   scan and target identifiers
-   creation time and deadline
-   targeted route/rule tasks in priority order
-   broader-coverage tasks
-   task-to-finding and task-to-route evidence links
-   selection reasons
-   estimated task counts, if available
-   planner version and rule-mapping version

The plan is a schedule, not a prediction that a vulnerability exists.

### 6.6 Optional GraphCodeBERT-Assisted Code Context Enrichment

GraphCodeBERT is an optional intelligence layer between deterministic
route/finding candidate mapping and final task ranking. It is intended to
help rank ambiguous code contexts and provide a learned relevance signal
for the planner. It is not a new scanner and is not part of the correlation
proof.

#### Why it may help

AST gives the architecture structural facts: route declarations, methods,
handler/helper scopes, and statically observed request parameters. Semgrep
gives suspicious source locations and rule/CWE metadata. In shared-helper
or multi-route cases, several candidates may be structurally plausible.
GraphCodeBERT's pretraining incorporates code tokens and data-flow
information (relationships describing where variable values come from),
which makes it a reasonable candidate model for contextual code ranking.

For example, two routes may call the same helper. AST should retain both
routes as candidates. A task-specific GraphCodeBERT relevance model may
help rank the route context whose input-handling and helper call context
best aligns with the Semgrep finding. The model must not remove the other
candidate solely because its score is lower.

#### Correct position in the workflow

1. AST and Semgrep run as they do today.
2. The deterministic mapper creates zero or more candidate route/finding
   relationships using target ID, file/line scope, handler/helper scope,
   and available parameter evidence.
3. For eligible candidates, the code-intelligence module prepares a
   focused code context and compatible data-flow representation.
4. GraphCodeBERT produces representations which a task-specific ranking
   head can use to score candidate relevance.
5. The planner uses that score only as an advisory ranking signal, within
   deterministic evidence tiers.
6. ZAP rule selection remains constrained by the verified CWE/sink-to-ZAP
   policy allowlist and the route's input surface.

GraphCodeBERT must not invent candidate routes. If AST cannot map a finding
to a route, the finding remains `UNRESOLVED`; a model similarity score
cannot promote it into a mapped route.

#### What the model does and does not do

| Suitable use | Not a supported assumption |
|---|---|
| Rank AST-produced candidate route/finding contexts | Discover every route or prove reachability |
| Add a learned context signal for likely input-to-operation relevance | Perform complete interprocedural taint analysis out of the box |
| Help prioritize among already verified ZAP rule families | Generate or invent ZAP rule IDs |
| Provide an optional feature for later task-specific fine-tuning | Classify a finding as exploitable or `Confirmed` |

GraphCodeBERT is pretrained for code representation tasks, not delivered
as a ready-made security classifier. A useful relevance score requires a
task-specific head and evaluation data. Do not label a raw embedding
similarity as a calibrated probability or as “confidence” unless it has
been calibrated and validated for this task.

#### Data-flow preparation

- Reuse AST-derived function boundaries and route/helper metadata.
- Build focused, function-level data-flow contexts for selected findings,
  using a parser/preprocessor compatible with the GraphCodeBERT reference
  implementation.
- Preserve the variable-definition/use relationships required by the
  model's data-flow input convention.
- Keep cross-function call/argument/return relationships as explicit AST
  call-graph metadata. Do not fabricate custom interprocedural graph edges
  unless the model input implementation supports and validates them.
- Process handler and helper contexts separately when necessary, then
  associate their assessments through the deterministic route candidate.
- Keep source file, line range, variable/parameter names, and preprocessing
  version attached to every assessment so results can be audited.

The standard `microsoft/graphcodebert-base` checkpoint is a 12-layer,
768-hidden-dimension model with 12 attention heads and a 512-token maximum
sequence length in its published model card. The original work describes
using data flow as part of the model input. Therefore, implementation must
use the compatible preprocessing and graph-input conventions; simply
passing arbitrary source text through a generic masked-language-model
pipeline does not reproduce the full data-flow-aware setup. See the
[model card](https://huggingface.co/microsoft/graphcodebert-base), the
[Microsoft implementation](https://github.com/microsoft/CodeBERT/tree/master/GraphCodeBERT),
and the [original paper](https://arxiv.org/abs/2009.08366).

For P06, Python/Flask is the first target. The original model was trained
on code from six languages, including Python, but that does not guarantee
security-ranking accuracy on this application's code or vulnerability
fixtures. Validate the preprocessing and task head on the actual Flask
fixtures before enabling model scores in scheduling.

#### Initial deployment modes

**Mode A — Shadow representations (recommended first):** Run the
pretrained encoder on eligible candidate contexts and store representations,
preprocessing metadata, and latency. Do not change task ordering. Any
experimental pairwise score remains non-authoritative.

**Mode B — Train and validate the task head:** Build manually reviewed
route/finding relevance pairs from the Flask fixtures, including hard
negative examples such as shared helpers reached by multiple routes. Train
a lightweight binary or pairwise ranking head over GraphCodeBERT
representations. Split data by application or source revision where
possible to reduce leakage, and keep a held-out evaluation set. Labels
should be manually adjudicated or grounded in trusted fixture evidence;
do not treat unreviewed AST candidate mappings as ground-truth labels.

**Mode C — Advisory ranking:** Only after the task head passes offline
validation and its score behavior is understood, allow it to rerank
candidates within the same deterministic priority tier. Exact
handler-scope matches with stronger parameter evidence must not be
overturned by a weaker structural candidate solely because of a model
score.

Do not start with a general “vulnerable vs safe” classifier. The first
useful learning task is narrower: **does this AST-produced route context
provide relevant code context for this Semgrep finding?** A separate,
carefully evaluated policy-family ranker may be considered later, but the
planner must still choose only from a verified ZAP policy allowlist.

#### Suggested assessment contract

```json
{
  "assessment_id": "generated-id",
  "scan_id": "scan-id",
  "target_id": "flask_demo",
  "finding_id": "semgrep-finding-id",
  "candidate_route_id": "route-id",
  "model_id": "microsoft/graphcodebert-base",
  "model_revision": "pinned-revision",
  "task_head_version": "route-relevance-v1",
  "preprocessor_version": "graphcodebert-dfg-v1",
  "source_revision": "git-commit-or-source-hash",
  "status": "AVAILABLE",
  "relevance_score": 0.0,
  "score_calibration": "UN_CALIBRATED",
  "evidence_refs": [
    {"file": "app/routes.py", "start_line": 10, "end_line": 28}
  ],
  "limitations": ["ONE_HOP_HELPER_CONTEXT"]
}
```

The numeric value is a placeholder, not a model result. `relevance_score`
may influence ranking only when the task head and score calibration have
been validated. `status` should support at least `AVAILABLE`,
`LOW_CONFIDENCE`, `SKIPPED`, and `ERROR`.

#### Runtime and cache controls

- Load the model lazily or in a separate worker so it does not increase
  the critical path for every scan.
- Run locally within the engine environment; source code should not be
  sent to an external inference service by default.
- Batch eligible candidate contexts where practical.
- Cache by source revision/hash, finding/context identity, model revision,
  task-head version, and preprocessing version. Invalidate on any change
  to those inputs.
- Enforce an inference time budget. If it is exceeded, the planner uses
  deterministic evidence only and continues.
- Record model load time, inference time, token/context truncation, cache
  hits, and failures.
- Treat model output as untrusted advisory data; validate its schema and
  never use generated text as a command, URL, or ZAP policy identifier.

#### Planner integration and precedence

The model score is not added as an arbitrary fixed percentage to Semgrep
severity. Until calibrated data justifies a numeric weighting, use this
precedence:

1. Deterministic evidence establishes eligibility and priority tier.
2. GraphCodeBERT may rerank candidates within a tier after validation.
3. Semgrep severity and stable rule-based tie-breakers remain visible.
4. Unmapped or unresolved candidates are not made route-mapped by the
   model; they remain eligible for ordinary broad coverage where safe.
5. Model absence, low confidence, or failure falls back to the
   deterministic planner without delaying ZAP.

Do not allow model scores to suppress findings or remove route/rule tasks
from the broader-coverage phase. The model improves ordering; it does not
reduce the safety net.

------------------------------------------------------------------------

## 7. Stage 4 --- Time-Budgeted ZAP Orchestration

ZAP performs the actual runtime checks. The orchestrator controls
ordering and the time available for scheduling additional work.

### 7.1 Two-phase execution

**Phase A: Targeted tests**

-   Execute the highest-priority route/rule tasks first.
-   Restrict requests to the selected target profile and authorized
    internal target origin.
-   Use the route's supported methods and input surfaces.
-   Capture ZAP alerts and progress events as soon as they are
    available.
-   Do not wait for every targeted task to finish before forwarding
    completed alerts to correlation.

**Phase B: Broader coverage**

-   After targeted tasks have been scheduled or completed, use the
    remaining time for broader route coverage.
-   Include routes that had no Semgrep mapping.
-   Use the configured broad ZAP policy and route scope.
-   Avoid repeating route/rule tasks already completed unless an
    explicit retry policy permits it.
-   Continue streaming alerts to the correlation engine.

The exact concurrency and phase transition policy should be configurable
and measured. The first implementation can use sequential or
bounded-concurrency scheduling to simplify safety and reproducibility.

### 7.2 Deadline handling

Define a scan-level deadline at scan creation.

The scheduler should:

1.  Reserve time for result flushing, correlation, and final report
    generation.
2.  Stop adding new tasks when the remaining budget reaches the
    configured cutoff.
3.  Allow in-flight requests to finish only within their configured
    request timeout and scan shutdown policy.
4.  Record tasks as `COMPLETED`, `FAILED`, `CANCELLED`,
    `SKIPPED_BUDGET`, or `TIMED_OUT`.
5.  Report incomplete coverage explicitly.

Do not describe the scan as complete merely because the time budget
expired.

### 7.3 What improves performance

The improvement is fewer low-value tests ahead of high-value tests.

For example, if a broad scan would schedule many route/rule combinations
before reaching a route with a Semgrep SQL injection finding, the
planner can schedule the relevant SQL injection checks on that route
earlier.

The SQL injection check itself is not assumed to run faster. The
architecture improves the time-to-first-relevant-test and the likelihood
that useful targeted evidence is collected before the deadline.

### 7.4 ZAP integration boundary

Keep ZAP as the DAST execution engine. Implement a thin orchestration
adapter that translates planner tasks into supported ZAP operations,
monitors job state, and normalizes alerts.

Before implementation, verify the installed ZAP version and API/add-on
support for:

-   selecting or restricting target URLs
-   selecting scan policies or rule IDs
-   controlling active scan scope
-   monitoring scan progress
-   retrieving alerts incrementally or through polling

If a capability is not supported by the installed ZAP integration, use
the narrowest supported alternative and document the limitation. Do not
invent a ZAP API endpoint or claim per-rule control without verifying
it.

------------------------------------------------------------------------

## 8. Stage 5 --- Incremental Correlation

The current architecture correlates normalized SAST and DAST findings as
a pipeline. The improvement is to make the same strict correlation logic
operate incrementally as ZAP alerts arrive.

### 8.1 Event flow

``` mermaid
sequenceDiagram
    participant P as DAST Planner
    participant Z as ZAP Orchestrator
    participant C as Correlation Engine
    participant S as Semgrep Findings
    participant A as AST Route Inventory
    participant UI as Frontend

    P->>Z: Submit prioritized ScanPlan
    Z->>Z: Start targeted route/rule tasks
    Z-->>C: ScanStarted
    C->>S: Load normalized SAST findings
    C->>A: Load RouteNode inventory
    Z-->>C: AlertDiscovered
    C->>C: Normalize and deduplicate alert
    C->>C: Apply strict correlation gate
    C-->>UI: FindingUpdated event
    UI->>UI: Update label, evidence, and counts
    Z->>Z: Continue targeted and broad phases
    Z-->>C: Additional alerts and task events
    C->>C: Re-evaluate affected records
    C-->>UI: Incremental updates
    Z-->>C: ScanFinished
    C->>C: Final reconciliation and report
    C-->>UI: ScanFinalized event
```

### 8.2 Incremental correlation behavior

When a new ZAP alert arrives:

1.  Normalize it into the existing `UnifiedFinding` schema.
2.  Check `target_id` and scan identity.
3.  Deduplicate using a stable alert identity.
4.  Parse its URL, method, and attacked parameter.
5.  Find candidate AST routes.
6.  Evaluate the existing strict correlation gate.
7.  If all required evidence matches, create or update a `Confirmed`
    pair.
8.  Otherwise retain it as an unmatched DAST finding, eligible for
    `Runtime only` classification under the existing classifier rules.
9.  Emit a finding update and update scan statistics.

When a scan starts, SAST and AST results should already be available to
the correlator. If they are not ready, buffer incoming DAST events until
the required evidence is loaded; do not silently classify incomplete
comparisons as final.

### 8.3 Preserve the strict confirmation gate

The existing architecture requires:

-   same `target_id`
-   same CWE
-   normalized route match
-   SAST file/line within a route code scope
-   attacked parameter supported by route parameter-read evidence
-   method and parameter source match when supplied

A CWE-only, route-only, or proximity-only match is not sufficient.

The incremental implementation must also preserve the existing
one-to-one DAST consumption rule: each DAST finding can be consumed by
at most one SAST finding in a run.

### 8.4 Reconciliation and late evidence

A DAST alert may arrive before another alert that would be a better
match for a SAST finding. To avoid order-dependent results:

-   retain candidate matches until the relevant scan evidence is stable;
-   use deterministic tie-breaking when more than one SAST finding is
    eligible;
-   prevent one DAST alert from being consumed twice;
-   support a final reconciliation pass at scan completion;
-   emit correction/update events if final reconciliation changes a
    provisional association.

A provisional match may be shown in the UI, but it must not be presented
as final `Confirmed` until the strict gate and deterministic assignment
policy have been applied.

------------------------------------------------------------------------

## 9. Proposed Data Contracts

These are additive contracts for the new planner and orchestration
workflow. Existing v1.3 schemas remain the baseline.

### 9.1 ScanPlan

``` json
{
  "scan_id": "scan-id",
  "target_id": "flask_demo",
  "planner_version": "1.0",
  "created_at": "ISO-8601 timestamp",
  "deadline_at": "ISO-8601 timestamp",
  "targeted_tasks": [],
  "broad_tasks": [],
  "code_intelligence": {
    "mode": "SHADOW",
    "model_id": "microsoft/graphcodebert-base",
    "model_revision": "pinned-revision",
    "task_head_version": null,
    "preprocessor_version": "graphcodebert-dfg-v1"
  },
  "status": "PLANNED"
}
```

### 9.2 ScanTask

``` json
{
  "task_id": "task-id",
  "scan_id": "scan-id",
  "target_id": "flask_demo",
  "route_id": "route-id",
  "normalized_url": "/api/orders/{param}",
  "method": "POST",
  "parameter": "customer",
  "parameter_source": "query",
  "zap_rule_id": "verified-rule-id",
  "phase": "TARGETED",
  "priority_score": 0,
  "reason_codes": ["SAST_CWE_MATCH", "ROUTE_SCOPE_MATCH"],
  "code_context_assessment_id": null,
  "model_ranking_used": false,
  "model_relevance_score": null,
  "status": "QUEUED",
  "started_at": null,
  "finished_at": null
}
```

### 9.3 ScanEvent

``` json
{
  "event_id": "event-id",
  "scan_id": "scan-id",
  "target_id": "flask_demo",
  "event_type": "ALERT_DISCOVERED",
  "occurred_at": "ISO-8601 timestamp",
  "task_id": "task-id",
  "finding_id": "finding-id",
  "payload": {}
}
```

Suggested event types:

-   `SCAN_STARTED`
-   `PHASE_STARTED`
-   `TASK_STARTED`
-   `TASK_COMPLETED`
-   `TASK_FAILED`
-   `ALERT_DISCOVERED`
-   `FINDING_UPDATED`
-   `BUDGET_CUTOFF`
-   `SCAN_FINISHED`

### 9.4 Finding lifecycle metadata

Add scan lifecycle fields without overloading the existing finding
label:

-   `scan_id`
-   `first_seen_at`
-   `last_updated_at`
-   `correlation_status`: `PENDING`, `PROVISIONAL`, `FINAL`
-   `matched_sast_ids`
-   `matched_dast_ids`
-   `correlation_version`

Keep `label` for the existing three-label classification. A finding's
scan-processing status is not the same thing as its vulnerability
classification.

------------------------------------------------------------------------

## 10. API and Module Changes

### 10.1 Suggested API additions

  ------------------------------------------------------------------------
  Endpoint                             Purpose
  ------------------------------------ -----------------------------------
  `POST /api/scans`                    Create a scan and generate its plan

  `GET /api/scans/{scan_id}`           Read scan status, phases, budget,
                                       and task counts

  `GET /api/scans/{scan_id}/plan`      Inspect targeted and broad tasks
                                       with reason codes

  `POST /api/scans/{scan_id}/cancel`   Request safe cancellation

  `GET /api/scans/{scan_id}/events`    Stream scan and finding events
                                       using SSE
  ------------------------------------------------------------------------

Existing endpoints such as `/api/graph`, `/api/findings`, and
`/api/findings/{id}` can remain available. They should expose the latest
scan-aware state where applicable.

### 10.2 Suggested engine modules

``` text
engine/
  ast_mapper/
    flask_adapter.py
    route_schema.py
    parameter_extractor.py

  ingestion/
    semgrep_parser.py
    zap_parser.py
    schema.py

  code_intelligence/                 # Optional, advisory-only
    graphcodebert_model.py             # Model loading/inference wrapper
    code_preprocessor.py               # Versioned model-compatible preprocessing
    dataflow_extractor.py              # Focused function-level DFG inputs
    context_builder.py                 # Finding + route/helper context windows
    relevance_head.py                  # Task-specific route/finding ranker
    assessment_schema.py
    cache.py

  dast_planner/
    planner.py
    rule_mapping.py
    priority.py
    plan_schema.py

  zap_orchestrator/
    client.py
    scheduler.py
    task_runner.py
    event_adapter.py
    budget.py

  correlation/
    correlator.py
    incremental.py
    reconciliation.py
    deduplication.py

  scan_manager/
    state.py
    coordinator.py
    event_store.py
```

Module names are a proposed organization. Existing modules should be
extended or moved only when doing so improves separation of
responsibility without disrupting the current implementation. Keep
`code_intelligence/` optional: the deterministic planner must work when
the model package, weights, or accelerator are unavailable.

------------------------------------------------------------------------

## 11. Frontend Improvements

Add a scan progress view to the existing React Correlation Workbench.

Display:

-   current phase: `Planning`, `Targeted`, `Broad coverage`, or
    `Finalizing`
-   elapsed time and remaining time
-   targeted tasks completed / queued / failed
-   broader-coverage tasks completed / queued
-   routes covered versus routes discovered
-   alerts received
-   findings updated incrementally
-   coverage gaps caused by budget cutoff
-   why a route/rule task was prioritized
-   whether GraphCodeBERT ran, was skipped, or fell back
-   model/task-head version and whether the score is calibrated, when
    advisory ranking is enabled
-   the deterministic evidence tier separately from any model ranking

Finding detail should show the Semgrep rule, source location, mapped
route, parameter evidence, selected ZAP rule, and any resulting HTTP
evidence. When model enrichment is enabled, show its result as an
advisory ranking signal with source-context references; do not display an
uncalibrated score as vulnerability confidence.

Do not imply that a route is safe merely because its task was not
reached before the deadline.

------------------------------------------------------------------------

## 12. Safety, Isolation, and Operational Invariants

Retain the existing v1.3 security boundaries:

1.  Only scan the explicitly selected target profile.
2.  Use the matching read-only source mount for that target.
3.  Keep target services on the internal Docker network.
4.  Route all ZAP traffic through the engine and selected target origin.
5.  Do not allow planner input or Semgrep metadata to override the
    configured target origin.
6.  Validate every planned URL against the selected target's allowed
    origin and route inventory.
7.  Do not follow redirects outside the authorized target origin.
8.  Apply request timeouts, bounded concurrency, and cancellation.
9.  Keep an audit record of planned tasks, executed tasks, alerts, and
    correlation updates.
10. Never merge findings across different `target_id` values.
11. Keep model inference local to the engine by default; do not upload
    proprietary target source to an external model endpoint.
12. Pin model weights, tokenizer, preprocessing code, and task-head
    versions so assessments are reproducible.
13. Treat source code, comments, identifiers, and model outputs as
    untrusted data. They must not be interpreted as instructions or
    allowed to alter scan scope, target origin, or executable commands.
14. Model scores must never authorize active scanning or weaken
    correlation requirements.

The planner is a prioritization component, not an authorization
component. The ZAP orchestrator must independently enforce target
boundaries. The code-intelligence module is an optional ranking component,
not an authorization, vulnerability-confirmation, or suppression layer.

------------------------------------------------------------------------

## 13. Failure Handling and Fallbacks

  -----------------------------------------------------------------------
  Failure                             Required behavior
  ----------------------------------- -----------------------------------
  AST parsing fails for a module      Mark affected routes unresolved;
                                      continue with routes that were
                                      parsed successfully

  Semgrep produces no findings        Skip targeted SAST-driven tasks and
                                      proceed to broad coverage

  Semgrep finding maps to no route    Preserve it as `Code only`
                                      candidate; do not invent a route

  Rule mapping is missing             Mark the task unsupported/unmapped;
                                      use a verified broader policy if
                                      appropriate

  GraphCodeBERT weights or runtime    Skip model enrichment and continue
  are unavailable                     with deterministic planner ranking

  GraphCodeBERT inference times out   Mark assessment `SKIPPED` or `ERROR`;
                                      do not delay the scan

  Model context exceeds token budget  Build a focused, versioned context;
                                      do not silently truncate the finding
                                      location or relevant parameter

  Model score is uncalibrated         Keep it in shadow mode; do not use it
                                      to alter scheduling

  ZAP targeted task fails             Record failure and continue
                                      eligible tasks within budget

  ZAP cannot expose alerts            Poll at a bounded interval and feed
  incrementally                       newly observed alerts to
                                      correlation

  Correlator is temporarily           Buffer events durably or in a
  unavailable                         bounded queue; apply backpressure
                                      rather than dropping alerts
                                      silently

  Time budget expires                 Stop scheduling, flush received
                                      alerts, reconcile, and report
                                      incomplete coverage

  Target health check fails           Do not start active scanning;
                                      report target unavailable

  Target origin validation fails      Reject the task and record a
                                      security event
  -----------------------------------------------------------------------

A failure in targeted planning must not silently broaden the target
scope.

------------------------------------------------------------------------

## 14. Metrics and Evaluation

Measure the proposed improvement against the current broad-first
baseline using the same target, ZAP configuration, and time budget.

### Primary metrics

  -----------------------------------------------------------------------
  Metric                              What it measures
  ----------------------------------- -----------------------------------
  Time to first targeted test         How quickly the first high-priority
                                      route/rule task starts

  Time to first relevant alert        Time until a relevant DAST alert is
                                      available, if one exists

  Targeted task completion count      How much prioritized work completes
                                      within the budget

  Relevant-route coverage             Fraction of Semgrep-mapped routes
                                      tested

  Broad-route coverage                Fraction of remaining routes tested

  Alert yield by phase                Alerts discovered in targeted
                                      versus broad phases

  Correlation latency                 Time from alert discovery to
                                      correlation update

  Final confirmed findings            Strictly correlated findings after
                                      reconciliation

  Incomplete task count               Tasks skipped, cancelled, or
                                      unfinished at cutoff

  Duplicate alert rate                Repeated alerts removed by
                                      deduplication
  -----------------------------------------------------------------------

### Fair comparison

Compare:

-   broad-first scan using the existing configuration;
-   targeted-first scan using the planner;
-   identical target image and source revision;
-   identical ZAP version, add-ons, and rule configuration;
-   identical request timeout and concurrency limits;
-   identical total wall-clock budget.

Report both total findings and findings available at intermediate time
checkpoints. A targeted strategy may improve early useful coverage
without necessarily changing the final result when both strategies are
allowed to run to completion.

Do not claim a speedup based only on the number of targeted tasks. Use
measured wall-clock times and alert data.

### GraphCodeBERT ablation

Evaluate the following configurations on the same fixtures, source
revision, ZAP version/policies, concurrency, and scan budget:

| Configuration | Purpose |
|---|---|
| A. AST + Semgrep + broad-first ZAP | Existing baseline |
| B. AST + Semgrep + targeted-first ZAP | Isolate the scheduling improvement |
| C. AST + Semgrep + GraphCodeBERT shadow mode + targeted ZAP | Measure model overhead and ranking quality without changing scheduling |
| D. AST + Semgrep + validated GraphCodeBERT reranking + targeted ZAP | Measure incremental benefit from model-assisted ranking |

Keep a held-out set of route/finding examples. Measure whether GraphCodeBERT
improves top-k candidate ranking and time-to-relevant-alert, and whether
that gain exceeds inference overhead. Report model-off fallback behavior.
Do not claim that GraphCodeBERT improves vulnerability detection unless
held-out results demonstrate it.

------------------------------------------------------------------------

## 15. Implementation Plan

### Phase 1 — Deterministic route and finding evidence

- Reuse and validate the Flask AST route inventory.
- Ensure route records include methods, code scopes, and request
  parameter reads.
- Normalize Semgrep findings with stable IDs, CWE, rule, file, and line
  metadata.
- Add tests for exact-scope, helper-scope, shared-helper, and
  unresolved mappings.
- Establish the broad-first baseline metrics before introducing model
  inference.

### Phase 2 — GraphCodeBERT in shadow mode

- Pin the `microsoft/graphcodebert-base` model revision and reference
  preprocessing implementation.
- Build focused function-level contexts and compatible data-flow inputs.
- Preserve cross-function relationships as explicit AST/call-graph
  metadata; do not assume the pretrained model performs full
  interprocedural taint analysis.
- Generate labelled route/finding relevance pairs from the Flask fixtures
  and manually review ambiguous examples.
- Implement inference, caching, resource/time limits, and assessment
  logging.
- Run in shadow mode: scores must not affect route/rule scheduling.
- Measure latency, context truncation, ranking quality, and fallback rate.

### Phase 3 — Planner and rule selection

- Build and version the Semgrep/CWE/sink-to-ZAP-policy mapping.
- Implement route/rule task generation.
- Implement deterministic priority classes and reason codes.
- Add optional model reranking only after the task-specific head has
  passed held-out validation; allow reranking within a deterministic tier
  only.
- Keep model-off fallback as the default safe path.
- Add plan serialization and inspection.
- Unit-test that unrelated or unsupported rules are not scheduled as
  targeted tasks.

### Phase 4 — ZAP orchestration

- Verify the installed ZAP API and add-on capabilities.
- Implement target validation and the selected-profile boundary.
- Execute targeted tasks first.
- Add deadline handling and broad-coverage fallback.
- Record every task state transition.

### Phase 5 — Incremental correlation

- Normalize ZAP alerts as they become available.
- Add event-driven correlation updates.
- Preserve strict matching and one-to-one DAST consumption.
- Add deterministic final reconciliation.
- Test out-of-order, duplicate, and late-arriving alerts.
- Ensure model scores are never read by the correlation confirmation
  gate.

### Phase 6 — UI and evaluation

- Add scan phase, task, and time-budget progress.
- Show planner reason codes and coverage gaps.
- Display model enrichment status separately from deterministic evidence.
- Stream finding updates to the workbench.
- Benchmark broad-first, targeted-first, shadow-model, and
  model-reranked configurations under identical conditions.
- Document measured results, model limitations, and model-off behavior.

## 16. Acceptance Criteria

The improvement is ready when:

-   [ ] Flask AST extraction provides routes, methods, handler scopes,
    and statically observed request parameters.
-   [ ] Semgrep findings retain stable source locations and
    vulnerability metadata.
-   [ ] Findings are mapped to routes only when source-scope evidence
    supports the mapping.
-   [ ] The planner creates explainable route/rule tasks with reason
    codes.
-   [ ] Targeted tasks are scheduled before broad-coverage tasks.
-   [ ] ZAP executes only against the selected authorized target
    profile.
-   [ ] Remaining scan time is allocated to broader coverage.
-   [ ] The scheduler stops adding work at the deadline and reports
    incomplete coverage.
-   [ ] ZAP alerts are passed to correlation incrementally, or via
    bounded polling if streaming is unavailable.
-   [ ] Incremental correlation preserves the existing strict evidence
    gate.
-   [ ] Duplicate and out-of-order alerts do not create duplicate
    confirmed pairs.
-   [ ] Final reconciliation produces deterministic results.
-   [ ] The UI shows progress, findings, and coverage gaps without
    treating untested routes as safe.
-   [ ] A controlled benchmark compares targeted-first and broad-first
    scans under the same conditions.
-   [ ] GraphCodeBERT is optional and can be disabled without affecting
    deterministic planning or ZAP execution.
-   [ ] Model preprocessing, model revision, task-head version, and source
    revision are recorded for reproducibility.
-   [ ] Model assessments can only rerank AST-produced candidates; they
    cannot invent route mappings or suppress findings.
-   [ ] Uncalibrated model outputs remain in shadow mode.
-   [ ] Model timeout, unavailable weights, or invalid output causes a
    deterministic fallback without delaying the scan.
-   [ ] The strict correlation gate does not consume GraphCodeBERT scores.
-   [ ] An ablation study reports ranking quality, inference overhead,
    time-to-relevant-alert, and fallback rate.

------------------------------------------------------------------------

## 17. Final Architecture Decision

The recommended change is an orchestration and scheduling improvement
around the existing scanner and correlation engine.

The new path is:

``` text
Flask AST route + parameter inventory
                 +
       Semgrep suspicious locations
                 |
                 v
       Route-to-finding mapping
                 |
                 v
       Optional GraphCodeBERT context ranking
       (advisory; deterministic evidence wins)
                 |
                 v
       DAST planner and rule selection
                 |
                 v
       Prioritized route/rule queue
                 |
                 v
       ZAP targeted phase first
                 |
                 v
       ZAP broader coverage with remaining time
                 |
                 v
       Incremental strict correlation
                 |
                 v
       Final reconciliation and classification
```

**The key insight remains:** targeted DAST does not make ZAP's
individual vulnerability tests magically faster. It reduces how many
unnecessary tests ZAP needs to perform before it reaches the routes and
checks that matter most.

GraphCodeBERT is an optional supporting layer: AST and Semgrep establish
the deterministic evidence; GraphCodeBERT may improve ranking among
existing candidates; the planner schedules tests; ZAP supplies runtime
evidence; and the strict correlation engine decides whether findings
match. Model failure must never stop the deterministic pipeline.

This preserves the strengths of architecture v1.3 while improving scan
ordering, early evidence availability, time-budget utilization, and the
responsiveness of the correlation workbench.


------------------------------------------------------------------------

## 18. GraphCodeBERT Technical References

These references support the model characteristics and integration
approach described in Section 6.6. They do not establish that the
pretrained checkpoint is a validated vulnerability detector for P06.

1. Guo et al., *GraphCodeBERT: Pre-training Code Representations with
   Data Flow*, ICLR 2021: https://arxiv.org/abs/2009.08366
2. Microsoft CodeBERT repository, GraphCodeBERT implementation and
   downstream-task preprocessing: https://github.com/microsoft/CodeBERT/tree/master/GraphCodeBERT
3. `microsoft/graphcodebert-base` model card and checkpoint details:
   https://huggingface.co/microsoft/graphcodebert-base

Before implementation, pin a specific model revision and inspect the
matching implementation revision. Do not rely on a moving `main` branch
for reproducible model preprocessing.
