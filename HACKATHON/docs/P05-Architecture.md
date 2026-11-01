# P06 Architecture — Mitigata SAST/DAST Correlation Engine

> **Status:** Current — reflects the implemented repo state as of the latest commit.
> **Version:** 2.0 — route-aware DAST planner, advisory GraphCodeBERT ranking, bounded verification workflow, scan manager, deduplication, incremental correlation, SARIF export, scan comparison
> **References:** [P06-PRD.md](P06-PRD.md) · [P06-SAST-DAST-Correlation-Engine.md](P06-SAST-DAST-Correlation-Engine.md) · [P06-Build-Plan.md](P06-Build-Plan.md)

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Container Topology](#2-container-topology)
3. [Data Flow Diagrams](#3-data-flow-diagrams)
4. [Component Deep-Dives](#4-component-deep-dives)
5. [Network Topology](#5-network-topology)
6. [Data Schemas](#6-data-schemas)
7. [API Contract](#7-api-contract)
8. [Performance Budget](#8-performance-budget)
9. [Dependency Graph](#9-dependency-graph)

---

## 1. System Overview

```mermaid
flowchart TD
    SAST["Semgrep SAST\nscan source code"]
    PARSE_S["semgrep_parser\nUnifiedFinding sast"]
    AST["Three-pass AST Route Mapper\nPass 1: routes + prefixes\nPass 2: handler + helper scopes\nPass 3: request parameter reads"]
    PLAN["DAST Planner\nScanPlan: targeted then broad\nadvisory GraphCodeBERT ranking"]
    ZAP["OWASP ZAP DAST\nscan running app\n5-min budget"]
    PARSE_Z["zap_parser\nUnifiedFinding dast"]
    DEDUP["deduplicate_findings\ncollapse repeated reports"]
    ENRICH["enrich_findings_with_ast\nset reachability flag"]
    CORR["Correlation Gate\ntarget + CWE + route + scope + parameter\nConfirmed / Corroborated / Code only / Runtime only"]
    CLF["Classifier + sort_findings\nConfirmed first\nrisk_score secondary sort"]
    UI["React UI\nCorrelation Workbench\nattack path graph"]

    SAST --> PARSE_S --> DEDUP
    PARSE_S --> AST
    AST --> PLAN --> ZAP --> PARSE_Z --> DEDUP
    DEDUP --> ENRICH
    AST --> ENRICH
    ENRICH --> CORR --> CLF --> UI
```

**Three mandatory objectives:**

| Objective | Key Deliverable | Scoring Weight |
|---|---|---|
| 01 — Scan Code & App | `UnifiedFinding` with `cwe_id` covering ≥ 4 CWE types | 30 pts (shared) |
| 02 — Correlate & Merge | Three-pass route mapper + strict correlation gate | 30 pts (shared) |
| 03 — Prioritise | Confirmed first in every view; ≥ 70% noise suppression | 20 pts (shared) |

---

## 2. Container Topology

```mermaid
graph TB
    subgraph HOST["Host Machine"]
        B["Browser :3000"]
        API_CLIENT["curl / CI :8000"]
    end

    subgraph PUB["Docker Network: public"]
        FE["mitigata-frontend\n:3000\nReact + Vite"]
        ENG["mitigata-engine\n:8000\nFastAPI + uvicorn"]
    end

    subgraph INT["Docker Network: internal (internal: true)"]
        FLASK["mitigata-target-flask\n:5050\nwe45 Vulnerable Flask App"]
        JUICE["mitigata-target-juice-shop\n:3001→3000\nOWASP Juice Shop · Express"]
    end

    B --> FE
    API_CLIENT --> ENG
    FE <--> ENG
    ENG -->|"profile-selected probes\ninternal network only"| FLASK
    ENG -->|"profile-selected probes\ninternal network only"| JUICE

    style INT fill:#1a0a0a,color:#fff
```

**Volume mounts (engine container):**

```yaml
volumes:
  - ./targets:/targets:ro        # read-only source for both adapters
  - ./configs:/app/configs:ro    # target profiles
  - ./data:/app/data             # raw scan output + verification results
```

---

## 3. Data Flow Diagrams

### 3.1 Main Pipeline — GET /api/graph

```mermaid
sequenceDiagram
    participant B as Browser
    participant FE as Frontend
    participant E as Engine
    participant T as Target (internal)

    B->>FE: GET localhost:3000
    FE->>E: GET /api/graph?target_id=flask_demo

    rect rgb(30, 50, 80)
        Note over E: Step 1 - SAST Ingestion (FR-1, FR-3)
        E->>E: semgrep_parser → sast UnifiedFinding[]
        E->>E: deduplicate SAST by target/CWE/file/line
    end

    rect rgb(30, 60, 50)
        Note over E: Step 2 - Three-Pass AST Route Mapper (FR-4)
        E->>E: Pass 1 - route declarations and prefix mounts
        E->>E: Pass 2 - handler and one-hop helper scopes
        E->>E: Pass 3 - request parameter reads
        E->>E: build_scan_plan - ScanPlan with targeted and broad tasks
        E->>E: GraphCodeBERT ranking if GRAPHCODEBERT_MODE=ON
    end

    rect rgb(60, 30, 50)
        Note over E: Step 3 - DAST (FR-2, FR-3) - runs AFTER SAST and route mapping
        E->>T: ZAP targeted tasks first (15s each)
        T-->>E: alerts JSON
        E->>T: ZAP broad fallback tasks (5s each, if budget remains)
        T-->>E: alerts JSON
        E->>E: zap_parser → dast UnifiedFinding[]
        E->>E: deduplicate DAST by target/CWE/rule/path/method/param
    end

    rect rgb(50, 40, 20)
        Note over E: Step 4 - Correlation and Classification (FR-5, FR-6, FR-7)
        E->>E: enrich_findings_with_ast - set reachable flag
        E->>E: correlate_and_merge - target+CWE+route+scope+parameter
        E->>E: apply persisted verification results
        E->>E: sort_findings - Confirmed first then risk_score
    end

    rect rgb(20, 40, 60)
        Note over E: Step 5 - Graph Build
        E->>E: ELK seed positions - GraphNode[] + GraphEdge[]
        E->>E: GraphStats - total, confirmed, suppression_ratio
        E-->>FE: GraphResponse with nodes, edges, stats
        FE-->>B: Correlation Workbench rendered in under 3s
    end
```

### 3.2 Live Verification Flow — SSE Stream

```mermaid
sequenceDiagram
    participant U as User
    participant FE as Frontend
    participant E as Engine
    participant V as Verification Workflow
    participant T as Target (internal)

    U->>FE: click "Verify" on Code only finding
    FE->>E: GET /api/verify/{finding_id}/stream?target_id=...
    E->>E: _verification_candidates: derive up to 4 route/method/param probes from AST

    loop for each candidate (up to 4)
        E->>V: iter_verification_states(AlertState)

        Note over V: probe_generator
        V->>V: select canary payload by sink_type + variant
        Note right of V: ssti → "{{7*7}}", sql → "'", xss → "<svg ...>"

        Note over V: runtime_executor
        V->>T: httpx.request(method, url, timeout=2.0s)
        T-->>V: HTTP response (capped at 500 bytes)

        Note over V: response_evaluator
        V->>V: check EVIDENCE_SIGNALS[sink_type]
        V->>V: ssti: "49" (exact, no template echo) / xss: "<svg" / sql: "operationalerror"

        alt Evidence found
            V-->>E: label = "Confirmed"
            E->>E: save_confirmed_result → data/raw/<target>-verification.json
            E-->>FE: SSE {label:"Confirmed", evidence, done:true}
            FE-->>U: badge flips 🟡 → 🔴 live
        else No evidence, variant == 0
            Note over V: retry_evaluator → variant = 1
            V->>V: loop with alternate payload
        else No evidence, variant == 1
            E-->>FE: SSE {label:"Code only", done:true}
        end
    end
```

### 3.3 Conditional Retry Flow

```mermaid
flowchart TD
    START(["Code only finding"]) --> PG["probe_generator\nvariant=0\npayload: {{7*7}}"]
    PG --> RE["runtime_executor\nhttpx timeout=2.0s\nno redirects, no env proxy"]
    RE --> EV["response_evaluator\ncheck EVIDENCE_SIGNALS"]

    EV --> DEC{"Evidence found?"}
    DEC -->|Yes| CONFIRMED(["Confirmed\nlabel updated\nSSE to UI"])
    DEC -->|"No, variant=0\nno non-retryable error"| RETRY["retry_evaluator\nvariant = 1"]
    DEC -->|"No, variant=1\nor non-retryable error"| CODEONLY(["Code only\nprobe inconclusive"])

    RETRY --> PG2["probe_generator\nvariant=1\nalternate canary"]
    PG2 --> RE2["runtime_executor"]
    RE2 --> EV2["response_evaluator"]
    EV2 -->|Evidence| CONFIRMED
    EV2 -->|No evidence| CODEONLY

    style CONFIRMED fill:#dc2626,color:#fff
    style CODEONLY fill:#ca8a04,color:#fff
```

### 3.4 Auto-Remediation Flow

```mermaid
flowchart LR
    SEL([User selects\nConfirmed finding]) --> CTX["Read ±40 lines source context\naround sink line"]
    CTX --> SARVAM{"SARVAM_API_KEY\nconfigured?"}
    SARVAM -->|Yes| LLM["Sarvam GLM-5.3\nunified diff\ntemp=0, 10s timeout"]
    SARVAM -->|No| TPL["Deterministic template\nfrom PATCH_TEMPLATES\nzero cost, always works"]

    LLM --> VALID{"Valid unified diff?\nstarts with --- or @@\nbounded single-file"}
    VALID -->|Yes| DIFF["Show Git diff preview in UI\nstored in _PATCH_PREVIEWS"]
    VALID -->|No| TPL
    TPL --> DIFF

    DIFF --> APPLY["User clicks Apply\napply_unified_diff()\nvalidate a/ b/ paths"]
    APPLY --> REVERIFY["Re-run same canary probe\nclear verification store\nclear graph cache"]
    REVERIFY --> RESULT{"Probe blocked?"}
    RESULT -->|Yes| FIXED(["✅ Fix Verified\nVulnerability Closed"])
    RESULT -->|No| INSUFF(["❌ Fix Insufficient\nRe-patch Required"])

    style FIXED fill:#16a34a,color:#fff
    style INSUFF fill:#dc2626,color:#fff
```

---

## 4. Component Deep-Dives

### 4.1 Ingestion Pipeline — FR-1, FR-2, FR-3

```mermaid
flowchart LR
    subgraph SAST_IN["FR-1: SAST Input"]
        SJ["data/raw/<target>-semgrep.json\nor data/sample/<target>_semgrep.json\ncheck_id · path · line · metadata.cwe · severity"]
    end

    subgraph DAST_IN["FR-2: DAST Input"]
        ZJ["data/raw/<target>-zap.json\nor data/sample/<target>_zap.json\ncweid · url · method · param · evidence · riskdesc"]
    end

    subgraph PARSE["FR-3: Normalise to Common Format"]
        SP["semgrep_parser.py\nextract CWE from metadata\nmap check_id → CWE fallback\nlabel = Code only"]
        ZP["zap_parser.py\nnormalise cweid → CWE-N\nnormalise riskdesc → severity\nlabel = Runtime only\ntarget-wide CORS/CSP collapse"]
        DEDUP["deduplicate_findings\nSAST: target/CWE/file/line\nDAST: target/CWE/rule/path/method/param\nretains merged_from + evidence_items"]
    end

    subgraph OUT["UnifiedFinding (common format)"]
        UF["id (stable uuid5 fingerprint)\ntarget_id · source · cwe_id\nlabel · file · line · function · sink_type\nurl · method · route · parameter\nevidence · evidence_items · payload\nseverity · reachable · routes\nmerged_from · reason · confidence"]
    end

    SJ --> SP --> DEDUP
    ZJ --> ZP --> DEDUP
    DEDUP --> UF
```

**Stable finding IDs:** `graph.py` derives each finding's ID as `uuid5(NAMESPACE_URL, fingerprint)` from `target_id + source + index + rule_id + cwe_id + file + line + url + method + parameter`. This makes IDs stable across API calls so the UI can safely use them for detail selection and verification.

**Parameterised query suppression (B-2):** `_has_bound_sql_parameters` inspects the Python AST at the reported line. Only a `cursor.execute()` call with a static string query, a recognised bind marker (`?`, `%s`, `:name`, `$N`), and an explicit second argument (tuple/list/dict/name) is suppressed. Unknown or dynamic query construction remains reportable.

### 4.2 Three-Pass AST Route Mapper — FR-4

```mermaid
flowchart TD
    SRC["Read-only target source\n(volume mount)"]

    subgraph P1["Pass 1: Route and prefix mapping"]
        PARSE1["Parse target modules\nPython ast module or\nNode.js TypeScript Compiler API"]
        DECL["Extract Flask @app.route / @bp.route / Blueprint\nor Express app.get/post, router.route(), router.get/post"]
        PREFIX["Resolve Flask url_prefix mounts\nor static Express app.use(prefix, router)"]
        NORMAL["Join prefix + route path\nNormalize: <int:id> and :id → {param}\nPreserve original path for diagnostics"]
        R1["RouteNode identity:\nnormalized_url + methods + handler\ntarget_id + resolved flag"]
    end

    subgraph P2["Pass 2: One-hop callee scopes"]
        HANDLER["Resolve route handler function"]
        CALLEE["Resolve directly called local/imported\nproject helpers (one hop only in v1)"]
        SCOPES["CodeScope[]: target-relative file\nstart_line + end_line + function"]
    end

    subgraph P3["Pass 3: Request parameter reads"]
        READ["Inspect handler + one-hop helper ASTs"]
        PARAMS["ParameterRead[]: name + source\nFlask: request.args/form/json/headers/view_args\nExpress: req.params/query/body/headers"]
    end

    NODE["Unified RouteNode\ntarget_id · raw_url · normalized_url\nmethods · handler · resolved\nscopes[] · input_parameters[]"]

    SRC --> PARSE1
    PARSE1 --> DECL --> PREFIX --> NORMAL --> R1
    R1 --> NODE
    HANDLER --> CALLEE --> SCOPES --> NODE
    READ --> PARAMS --> NODE
```

**Key constraints:**
- Pass 2 resolves only **direct** local/imported callees — no transitive chains claimed
- Dynamic/unresolved mount paths remain `resolved=False` and cannot match DAST traffic
- Unresolved request keys (e.g. `request.args.get(some_var)`) are not recorded as `ParameterRead`
- Header parameter names are compared case-insensitively; all other parameter names are case-sensitive

### 4.3 Correlation & Merge Engine — FR-5, FR-6

```mermaid
flowchart TD
    SAST["SAST findings\ntarget_id + CWE + file + line"]
    DAST["DAST findings\ntarget_id + CWE + URL + method + parameter"]
    ROUTES["RouteNode[]\nnormalized URL + methods\nCodeScope[] + ParameterRead[]"]

    DEDUP_PRE["deduplicate_findings\nbefore correlation"]
    ENRICH["enrich_findings_with_ast\nset reachable flag on SAST findings"]

    CANDIDATE{"For each SAST/DAST pair:\nsame target_id AND same CWE?"}
    ROUTE_MATCH{"Normalized DAST path\nmatches RouteNode?\nMethod matches when known?"}
    SCOPE_MATCH{"SAST file:line inside\nhandler or one-hop helper scope?"}
    PARAM_MATCH{"DAST attacked parameter\nread by this route?\nSource kind matches when supplied?"}

    CONFIRMED["Confirmed\nmerge SAST+DAST evidence\nmerged_from = [sast.id, dast.id]\nconfidence = 0.95\nconsumed_dast_ids.add(dast.id)"]
    CODE_ONLY["Code only\npreserve reachable flag\nno DAST consumed"]
    RUNTIME_ONLY["Runtime only\nunconsumed DAST findings"]
    SORT["sort_findings\nConfirmed → Corroborated → Code only → Runtime only\nthen by risk_score, confidence"]

    SAST --> DEDUP_PRE --> ENRICH
    DAST --> DEDUP_PRE
    ROUTES --> ENRICH
    ENRICH --> CANDIDATE
    DAST --> CANDIDATE
    ROUTES --> ROUTE_MATCH
    CANDIDATE -->|Yes| ROUTE_MATCH
    CANDIDATE -->|No candidate| CODE_ONLY
    ROUTE_MATCH -->|Yes| SCOPE_MATCH
    ROUTE_MATCH -->|No| CODE_ONLY
    SCOPE_MATCH -->|Yes| PARAM_MATCH
    SCOPE_MATCH -->|No| CODE_ONLY
    PARAM_MATCH -->|Yes| CONFIRMED
    PARAM_MATCH -->|No| CODE_ONLY
    CONFIRMED --> SORT
    CODE_ONLY --> SORT
    DAST --> RUNTIME_ONLY
    CONFIRMED -.->|"consumed_dast_ids\nprevents double-merge"| RUNTIME_ONLY
    RUNTIME_ONLY --> SORT
```

**Corroborated label:** When `target_id`, CWE, route, and source location agree but request-input evidence is incomplete (parameter name missing or source kind absent), the pair is labelled `Corroborated` at confidence 0.7 rather than `Confirmed`. This is a lower-confidence intermediate state between Code only and Confirmed.

**CWE normalisation:** `CWE-079` and `CWE-79` are treated as equal. Different CWE numbers are never treated as equivalent.

### 4.4 DAST Planner — ScanPlan / ScanTask / ScanEvent

```mermaid
flowchart TD
    SAST_F["SAST findings\n(after dedup)"]
    ROUTES_P["RouteNode[]\n(resolved only)"]
    BUDGET["budget_minutes=5\ndeadline_at (UTC ISO)"]

    subgraph PRIORITY["Priority Classification"]
        P0["Priority 0\nROUTE_SCOPE_MATCH\n+ PARAMETER_SURFACE_MATCH\nexact handler scope + supported inputs"]
        P1["Priority 1\nHELPER_SCOPE_MATCH\n+ PARAMETER_SURFACE_MATCH\nhelper scope + supported inputs"]
        P2["Priority 2\nROUTE_SCOPE_MATCH\n+ INPUT_EVIDENCE_INCOMPLETE\nmatching route, no param evidence"]
        P3["Priority 3\nMULTIPLE_ROUTE_CANDIDATES\n→ GRAPHCODEBERT_TIEBREAK\nambiguous, model breaks tie"]
        P4["Priority 4\nBROAD_COVERAGE\nno SAST match"]
    end

    subgraph TASKS["ScanTask generation"]
        TGT["Targeted tasks\ncoalesced by route+method\nall applicable ZAP rule IDs\n15s ceiling each"]
        BROAD["Broad tasks\nexclude targeted rule IDs\n5s ceiling each\nonly if budget remains"]
    end

    subgraph MODEL["GraphCodeBERT (advisory)"]
        GCB["shadow_ranker.assess_candidates\nPriority 3 only\ncosine similarity score\nUNCLAIBRATED\nnever overrides gate"]
    end

    PLAN["ScanPlan\nscan_id · target_id · target_url\nplanner_version · rule_mapping_version\ncreated_at · deadline_at\ntargeted_tasks[] · broad_tasks[]\nunresolved_finding_ids[]\ncode_intelligence · intelligence_assessments"]

    SAST_F --> PRIORITY
    ROUTES_P --> PRIORITY
    BUDGET --> PLAN
    PRIORITY --> P0 & P1 & P2 & P3 & P4
    P0 & P1 & P2 & P3 --> TGT
    P4 --> BROAD
    P3 --> MODEL --> TGT
    TGT & BROAD --> PLAN
```

**ZAP rule mapping:**

| CWE | ZAP Rule IDs |
|---|---|
| CWE-22 | 6 |
| CWE-78 | 90020 |
| CWE-79 | 40012, 40014 |
| CWE-89 | 40018 |
| CWE-601 | 20019 |

### 4.5 Runtime Verification Workflow

```mermaid
stateDiagram-v2
    [*] --> probe_generator : Code only finding\n(eligible sink type)

    probe_generator : probe_generator\nselect payload by sink_type\nvariant 0=primary, 1=retry\nNON_PROBEABLE_SINKS → UNVERIFIED

    runtime_executor : runtime_executor\nhttpx.AsyncClient\nfollow_redirects=False, trust_env=False\ntimeout=2.0s HARD LIMIT\nGET/HEAD/OPTIONS/POST only\nresponse capped at 500 bytes

    response_evaluator : response_evaluator\ncheck EVIDENCE_SIGNALS[sink_type]\nsql: operationalerror, sqlite3, syntax error\nssti: 49 (exact match), jinja2, templateerror\nxss: <svg, <img, onload=, onerror=\ncmd: canary_mitigata_2026\nopen_redirect: Location header check

    retry_evaluator : retry_evaluator\nvariant += 1\nclear error + response

    probe_generator --> runtime_executor
    runtime_executor --> response_evaluator

    response_evaluator --> [*] : Evidence found\nlabel = Confirmed 🔴\nsave_confirmed_result()
    response_evaluator --> retry_evaluator : No evidence\nAND variant == 0\nAND no non-retryable error
    response_evaluator --> [*] : No evidence\nAND variant == 1\nlabel = Code only 🟡

    retry_evaluator --> probe_generator
```

**Non-probeable sinks** (no safe runtime signal): `hardcoded_secret`, `insecure_deserialisation`, `jwt_weak_secret`, `weak_hash`

**Non-retryable errors**: `invalid_target_profile`, `unsafe_http_method`, `invalid_route`, `invalid_parameter`, `invalid_parameter_source`, `unsupported_sink_type`, `path_parameter_not_found`

**Flask 404 handler special case:** The SSTI finding in `pnf(e)` (`@app.errorhandler(404)`) has no route decorator. `_is_flask_not_found_handler` detects it via AST and generates a synthetic probe candidate at `/__mitigata_not_found__/{probe_path}`.

### 4.6 3-Label Classifier — FR-7

```mermaid
flowchart TD
    INPUT([Finding after\ncorrelation + verification]) --> R1

    R1{"verification_label == Confirmed\nAND dual_confirmed?"}
    R1 -->|Yes| C1["🔴 Confirmed\nconfidence = 0.98\nSAST + DAST + route + CWE both match"]

    R1 -->|No| R2
    R2{"verification_label == Confirmed?"}
    R2 -->|Yes| C2["🔴 Confirmed\nconfidence = 0.90\nHTTP evidence captured"]

    R2 -->|No| R3
    R3{"is_config_only?\n(no code sink)"}
    R3 -->|Yes| C3["🟠 Runtime only\nconfidence = 0.85\nmissing headers / CORS / TLS"]

    R3 -->|No| R4
    R4{"ast_reachable == False?"}
    R4 -->|Yes| C4["🟡 Code only\nconfidence = 0.95\ndead code — suppressed (B-2)"]

    R4 -->|No| R5
    R5{"ast_reachable == True?"}
    R5 -->|Yes| C5["🟡 Code only\nconfidence = 0.70\nreachable but probe inconclusive"]

    R5 -->|No| C6["🟡 Code only\nconfidence = 0.50\nAST unknown — conservative"]

    style C1 fill:#dc2626,color:#fff
    style C2 fill:#dc2626,color:#fff
    style C3 fill:#ea580c,color:#fff
    style C4 fill:#ca8a04,color:#fff
    style C5 fill:#ca8a04,color:#fff
    style C6 fill:#ca8a04,color:#fff
```

**Risk score (0–100):** `severity_score × 0.7 + exploitability × 0.6` where exploitability accumulates from label (+20 Confirmed, +15 Runtime only, +10 Corroborated), reachability (+10), parameter evidence (+10), and HTTP evidence (+10). Used for secondary sort within each label tier.

### 4.7 Patch Engine — B-4

```mermaid
flowchart LR
    subgraph INPUT["Input"]
        FIND["Confirmed finding\nsink_type · file · line\ncode context ±40 lines\ncwe_id"]
    end

    subgraph CHAIN["Sarvam GLM-5.3 → Template fallback"]
        SARVAM["Sarvam Token Factory GLM-5.3\nSARVAM_BASE_URL + SARVAM_MODEL\ntemp=0 · 10s timeout · no SDK retries\nPrompt: sink_type + CWE + file + line + context\nNOT: target_id, scanner report, DAST payload"]
        VALID["Validate: bounded single-file unified diff\nvalid hunk counts\nexact repo-relative a/ b/ paths"]
        TPL["PATCH_TEMPLATES dict\nCWE-89: parameterised query\nCWE-79: markupsafe.escape\nCWE-78: subprocess list args\nCWE-94: render_template()\nCWE-347: env JWT secret\nCWE-916: bcrypt\nCWE-95: remove eval\nCWE-22: path resolve + check\nCWE-601: allowlist redirect\nCWE-502: data-only format"]
    end

    subgraph APPLY["Apply + Re-verify"]
        PREVIEW["_PATCH_PREVIEWS cache\nprevent replay attacks\npatch must match stored preview"]
        APPLY2["apply_unified_diff()\nvalidate a/ b/ paths\nwrite to source file"]
        REVERIFY["clear_target_verifications\nclear_graph_snapshot_cache\nRe-run same canary probe"]
        RESULT["PatchResult.kind:\nunified_diff or remediation_snippet\nneither applied automatically"]
    end

    FIND --> SARVAM
    SARVAM --> VALID
    VALID -->|Valid diff| PREVIEW
    VALID -->|Invalid / error| TPL
    TPL --> PREVIEW
    PREVIEW --> APPLY2 --> REVERIFY --> RESULT
```

### 4.8 Compliance Translator

```mermaid
flowchart TD
    FIND([Finding\ncwe_id · severity · label]) --> RISK & MAP

    subgraph RISK["Financial Risk (IBM 2024 India)"]
        PROB["breach_probability\nCRITICAL=85% · HIGH=65%\nMEDIUM=40% · LOW=15%"]
        EXP["total_exposure_inr\n= records × ₹5,000 × probability"]
        INS["cyber_insurance_impact\n= total_exposure_inr > ₹50,00,000"]
        INC06["INC-06 reference\n2017 Credit Bureau Breach\n145M records · ₹61,625 crore"]
    end

    subgraph MAP["4-Framework Compliance Mapping"]
        RBI["RBI CSF\nAnnex I §4.2 Input Validation\nAnnex I §4.3 IAM\nAnnex II Advanced Measures"]
        SEBI["SEBI CSCRF\nDomain 3: IAM\nDomain 5: Application Security"]
        ISO["ISO 27001:2022\nA.8.28 Secure coding\nA.8.5 Secure authentication\nA.5.17 Auth information"]
        DPDP["DPDP Act 2023\n§8(1) Reasonable safeguards\n§8(2) Unauthorised access\n§9 Children's data"]
    end

    RISK --> OUT
    MAP --> OUT
    OUT["ComplianceResponse\n{target_id, records_at_risk,\nfindings[], summary{framework: count}}"]
```

### 4.9 Scan Manager — Job Lifecycle

```mermaid
stateDiagram-v2
    [*] --> QUEUED : POST /api/scans
    QUEUED --> RUNNING : scan_jobs.start()
    RUNNING --> COMPLETED : scan finishes normally
    RUNNING --> INCOMPLETE : budget exceeded before all tasks run
    RUNNING --> FAILED : unhandled error
    COMPLETED --> [*] : clear_graph_snapshot_cache
    INCOMPLETE --> [*] : clear_graph_snapshot_cache
    FAILED --> [*]
```

**Scan job constraints:**
- Only one scan may run at a time per instance; `ScanAlreadyRunning` (HTTP 409) if a job is active
- `GET /api/scans/latest?target_id=...` polls job status and clears the graph cache on completion
- `GET /api/scans/compare?target_id=...` diffs the latest vs previous completed scan using target-scoped CWE + location/request-surface identity keys
- Finding history is stored in `data/raw/<target>-finding-history.json` (metadata only, no payloads)

### 4.10 FastAPI Engine Layer — FR-10

```mermaid
graph LR
    subgraph API["FastAPI Engine — http://localhost:8000"]
        G["GET /api/graph\nfull correlation graph\n≤10s · 10s cache TTL"]
        PL["GET /api/planner\nScanPlan preview\ndoes NOT start a scan"]
        SC["POST /api/scans\nstart SAST or DAST job\n202 Accepted"]
        SL["GET /api/scans/latest\njob status + phase counts"]
        SCJ["GET /api/scans/{job_id}\nsingle job status"]
        CMP["GET /api/scans/compare\nnew / fixed / still_open diff"]
        VS["GET /api/verify/{id}/stream\nSSE: probe_history + label flip\n≤2s/probe"]
        P["POST /api/patch\ngenerate unified diff\nSarvam → template fallback"]
        PA["POST /api/patch/apply\napply + re-verify\npreview must match"]
        C["GET /api/compliance\nINR + 4 frameworks\nper finding"]
        SAR["GET /api/export/sarif\nSARIF 2.1\nfail_on_confirmed_high → HTTP 409"]
        TGT["GET /api/targets\n[flask_demo, juice_shop]"]
        H["GET /health\nDocker healthcheck"]
        D["GET /docs\nSwagger UI"]
    end
```

### 4.11 React Frontend — FR-8, FR-9

```mermaid
graph TD
    subgraph APP["App.tsx — http://localhost:3000"]
        TS["TargetSelector\nflask_demo | juice_shop"]
        SB["StatsBar · active target_id\ntotal · confirmed · corroborated\ncode_only · runtime_only\nsuppression_ratio · cwe_types_covered"]

        subgraph LEFT["Correlation Graph Panel"]
            CG["CorrelationGraph.tsx\nReact Flow (@xyflow/react)\nELK layered layout\nConfirmed nodes first\nanimated edges for Confirmed"]
            NT["Node Types\nendpoint — HTTP route\ncontroller — handler function\nsink — vulnerable line\nevidence — HTTP proof\nsuppressed — dead code (grey)"]
        end

        subgraph RIGHT["Finding Detail Panel"]
            DP["FindingDetailPanel.tsx\nFR-8: URL+param+payload\nfile+line+CWE+snippet"]
            LB["LabelBadge\n🔴/🟡/🟠 + confidence %\nrisk_score 0-100"]
            CS["CodeSnippet\nsource_snippet ±7 lines\nsyntax highlighted"]
            HT["HttpTrace\nrequest + evidence + http_status"]
            VB["VerifyButton → B-1\nuseVerification() hook\nSSE EventSource → live flip"]
            PH["ProbeHistory\nexpandable audit log\nroute + parameter per attempt"]
            RB["RemediateButton → B-4\nDiffPreview unified diff\nApplyButton\nVerificationStatus ✅/❌"]
            REM["Remediation guidance\nper-CWE plain-English fix\nshown on every finding"]
        end

        subgraph PLAN["Planner Panel"]
            PP["PlannerPanel.tsx\nScanPlan preview\ntargeted_tasks + broad_tasks\nreason_codes + parameters\nGraphCodeBERT status"]
        end

        subgraph RISK["Business Risk Tab"]
            FR["FinancialRisk\n₹ exposure · breach_probability %"]
            CT["ComplianceTable\nRBI / SEBI / ISO / DPDP rows"]
            CI["CyberInsuranceFlag\nYES/NO badge"]
            IR["Inc06Reference\n2017 Credit Bureau callout"]
        end
    end

    TS --> SB
    SB --> LEFT & RIGHT & PLAN
    CG --> DP
    DP --> LB & CS & HT & VB & RB & REM
    VB --> PH
    DP --> RISK
```

---

## 5. Network Topology

```mermaid
graph TB
    subgraph HOST["Host Machine"]
        B["Browser :3000"]
        C["curl :8000"]
        X["curl :5050 ❌\ncurl :3001 ❌"]
    end

    subgraph PUB["Docker Network: public"]
        FE["mitigata-frontend\n:3000"]
        ENG["mitigata-engine\n:8000"]
    end

    subgraph INT["Docker Network: internal\ninternal: true"]
        FLASK["Flask target\nwe45/Vulnerable-Flask-App\n:5050 — NOT on public network"]
        JUICE["Juice Shop target\nOWASP Juice Shop · Express\n:3000 (internal) — NOT on public network"]
    end

    B --> FE
    C --> ENG
    X -. "connection refused" .-> FLASK
    X -. "connection refused" .-> JUICE
    FE <--> ENG
    ENG -->|"profile-selected probes only\ninternal network"| FLASK
    ENG -->|"profile-selected probes only\ninternal network"| JUICE

    style INT fill:#2d1515,color:#fff
    style X fill:#dc2626,color:#fff
```

**Probe route:** `engine (internal) → selected target (internal)` — never leaves Docker network. The engine uses only the configured `origin` from `configs/<target_id>.yaml`; finding URLs never supply the request host.

---

## 6. Data Schemas

### 6.1 UnifiedFinding — FR-3 Common Format

```mermaid
classDiagram
    class UnifiedFinding {
        +str id  stable uuid5 fingerprint
        +str target_id  flask_demo | juice_shop
        +str source  sast | dast
        +str cwe_id  MANDATORY e.g. CWE-89
        +str label  Confirmed|Corroborated|Code only|Runtime only
        +str file  target-relative path
        +int line  ≥ 1
        +str function  handler name
        +str sink_type  sql_injection | ssti | xss | ...
        +str url  full URL from DAST
        +str method  GET | POST | ...
        +str route  normalized route template
        +str parameter  attacked parameter name
        +str parameter_source  path|query|form|json|header
        +str payload  ZAP attack payload
        +str evidence  verification signal text
        +list evidence_items  per-alert evidence records
        +int http_status  HTTP response code
        +str rule_id  Semgrep check_id or ZAP rule id
        +str severity  CRITICAL|HIGH|MEDIUM|LOW|INFO
        +bool reachable  set by AST merger
        +list routes  normalized route templates
        +list merged_from  source finding IDs (FR-6)
        +str reason  human-readable correlation reason
        +float confidence  0.0–1.0
    }
```

### 6.2 RouteNode — FR-4 Route Mapping

```mermaid
classDiagram
    class RouteNode {
        +str target_id
        +str raw_url  original path from source
        +str normalized_url  {param} placeholders
        +str original_path  pre-normalization
        +list methods  HTTP verbs
        +str handler  module.function
        +bool resolved  False if dynamic mount
        +CodeScope[] scopes
        +ParameterRead[] input_parameters
        +matches_path(path) bool
        +matches_method(method) bool
        +contains_location(file, line) bool
    }

    class CodeScope {
        +str file  target-relative
        +int start_line
        +int end_line
        +str function
    }

    class ParameterRead {
        +str name  parameter name
        +str source  path|query|form|json|header
    }

    RouteNode "1" --> "1..*" CodeScope : handler and direct callees
    RouteNode "1" --> "0..*" ParameterRead : observed request inputs
```

### 6.3 ScanPlan / ScanTask

```mermaid
classDiagram
    class ScanPlan {
        +str scan_id  uuid4
        +str target_id
        +str target_url
        +str planner_version  1.0
        +str rule_mapping_version  1.0
        +str created_at  ISO UTC
        +str deadline_at  ISO UTC
        +ScanTask[] targeted_tasks  sorted by priority_score
        +ScanTask[] broad_tasks  sorted by normalized_url
        +list unresolved_finding_ids  SAST not mapped to any route
        +str status  PLANNED
        +dict code_intelligence  GraphCodeBERT metadata
        +list intelligence_assessments  per-candidate scores
    }

    class ScanTask {
        +str task_id  sha256[:20] of route+method+phase+rules
        +str target_id
        +str route_id
        +str raw_url
        +str normalized_url
        +str method
        +str phase  TARGETED | BROAD
        +int priority_score  0=highest
        +list reason_codes  SAST_CWE_MATCH etc.
        +list finding_ids  linked SAST finding IDs
        +list zap_rule_ids  ZAP scanner IDs
        +list excluded_zap_rule_ids  rules covered by targeted task
        +list parameters  name + source dicts
        +str parameter_limitation  unsupported input types
        +str status  QUEUED|RUNNING|COMPLETED|FAILED
    }

    ScanPlan "1" --> "0..*" ScanTask : targeted_tasks
    ScanPlan "1" --> "0..*" ScanTask : broad_tasks
```

### 6.4 AlertState — Verification Workflow

```mermaid
classDiagram
    class AlertState {
        +str finding_id
        +str target_id
        +str route  normalized route template
        +str method  GET | POST
        +str parameter  attacked parameter name
        +str parameter_source  path|query|form|json|header
        +str sink_type  sql_injection | ssti | ...
        +str probe_payload  canary string
        +int probe_variant  0=primary 1=retry
        +int http_status
        +str http_response  first 500 bytes
        +str http_location  Location header (redirect check)
        +str evidence  signals found in response
        +str label  Confirmed|Code only|UNVERIFIED
        +str error  error code if probe failed
        +list probe_history  ProbeRecord[]
    }

    class ProbeRecord {
        +int variant
        +str payload
        +int status
        +str response_preview  first 200 chars
        +str location  redirect destination
        +str error  if probe failed
    }

    AlertState "1" --> "0..*" ProbeRecord : probe_history
```

### 6.5 GraphResponse — API

```mermaid
classDiagram
    class GraphResponse {
        +str target_id
        +GraphNode[] nodes
        +GraphEdge[] edges
        +GraphStats stats
    }

    class GraphNode {
        +str id
        +str type  endpoint|controller|sink|evidence|suppressed
        +dict position  x, y (ELK seed coordinates)
        +GraphNodeData data
    }

    class GraphNodeData {
        +str label
        +str target_id
        +str finding_id
        +str finding_label
        +float confidence
        +str file
        +int line
        +list routes
        +list mapped_urls  full target URLs
        +str cwe
        +str evidence
        +list evidence_items
        +str payload
        +int risk_score  0-100
        +list merged_from
        +str reason
        +str url
        +str method
        +str parameter
        +str parameter_source
        +int http_status
        +str severity
        +str source
        +str source_snippet  ±7 lines of source
        +str sink_type
        +str function
        +str remediation  per-CWE fix guidance
    }

    class GraphEdge {
        +str id
        +str source
        +str target
        +bool animated  true for Confirmed
    }

    class GraphStats {
        +str target_id
        +int total
        +int confirmed
        +int corroborated
        +int code_only
        +int runtime_only
        +float suppression_ratio  0.0–1.0
        +list cwe_types_covered  Obj 01 proof
    }

    GraphResponse "1" --> "0..*" GraphNode : nodes
    GraphResponse "1" --> "0..*" GraphEdge : edges
    GraphResponse "1" --> "1" GraphStats : stats
    GraphNode "1" --> "1" GraphNodeData : data
```

---

## 7. API Contract

| Endpoint | Method | Description | Performance |
|---|---|---|---|
| `/api/graph` | GET | Full correlation graph for target profile | ≤ 10 s cold, ≤ 1 s cached (10 s TTL) |
| `/api/verify/{id}/stream` | GET | SSE verification stream; probe_history + label | ≤ 2 s per probe |
| `/api/patch` | POST | Generate unified diff (Sarvam → template) | ≤ 10 s |
| `/api/patch/apply` | POST | Apply approved patch + re-verify | ≤ 15 s total |
| `/api/compliance` | GET | INR exposure + 4 regulatory frameworks | < 200 ms |
| `/api/export/sarif` | GET | SARIF 2.1; `fail_on_confirmed_high=true` → HTTP 409 | < 1 s |
| `/api/planner` | GET | ScanPlan preview (no scan started) | ≤ 5 s |
| `/api/scans` | POST | Start SAST or DAST scan job | 202 Accepted |
| `/api/scans/latest` | GET | Latest job status + phase counts | < 100 ms |
| `/api/scans/{job_id}` | GET | Single job status | < 100 ms |
| `/api/scans/compare` | GET | new / fixed / still_open diff | < 200 ms |
| `/api/targets` | GET | `["flask_demo", "juice_shop"]` | < 10 ms |
| `/health` | GET | Docker healthcheck | < 10 ms |
| `/docs` | GET | Swagger UI | — |

**SSE event format:**

```json
// Intermediate update:
{"finding_id": "...", "target_id": "flask_demo", "label": "Code only", "probe_history": [...], "done": false}

// Final confirmed:
{"finding_id": "...", "target_id": "flask_demo", "label": "Confirmed", "evidence": "Response contained verification signals: 49", "probe_history": [...], "done": true}

// Error:
event: verification-error
{"finding_id": "...", "target_id": "flask_demo", "done": true, "error": "No safe probe is available for this sink..."}
```

---

## 8. Performance Budget

| Operation | Budget | Implementation |
|---|---|---|
| `docker compose up --build` | < 60 s | cached layers after first build |
| Target healthcheck | < 30 s | curl retry 3× with 10 s gap |
| `GET /api/graph` (cold) | **≤ 10 s** | AST parse + ELK seed layout |
| `GET /api/graph` (warm) | < 1 s | in-memory 10 s TTL cache |
| Single verification probe | **≤ 2 s** | `asyncio.timeout(2.0)` + `httpx.Timeout(2.0)` |
| Probe + retry | ≤ 4 s | 2 × 2 s probes |
| UI initial render | **≤ 3 s** | pre-computed ELK seed positions |
| Patch generation (Sarvam) | ≤ 10 s | 10 s timeout, no SDK retries |
| Patch generation (template) | < 50 ms | dict lookup |
| Patch apply + re-verify | **≤ 15 s** | within PRD budget |
| ZAP DAST window | **≤ 5 min** | targeted 15 s / broad 5 s per task |

---

## 9. Dependency Graph

```mermaid
graph TD
    subgraph ENGINE["engine/"]
        MAIN["api/main.py\nFastAPI app"]
        GRAPH["api/graph.py\nGraphSnapshot builder\n10s TTL cache"]

        subgraph ING["ingestion/"]
            SCHEMA["schema.py\nUnifiedFinding · Pydantic v2"]
            SP["semgrep_parser.py"]
            ZP["zap_parser.py"]
            CORR["correlator.py\ncorrelate_and_merge\nFR-5 FR-6"]
            DEDUP["deduplication.py\ndeduplicate_findings"]
            INC["incremental.py\nincremental DAST ingestion"]
        end

        subgraph AST["ast_mapper/ + adapters/"]
            RS["route_schema.py\nRouteNode · CodeScope · ParameterRead"]
            ADAPT["adapters/\nflask_adapter.py · express_adapter.py\nbase.py RouteAdapter Protocol"]
            SD["sink_detector.py"]
            CG["call_graph.py\nbuild_call_graph\ndispatch Flask or Express"]
            MG["merger.py\nenrich_findings_with_ast"]
        end

        subgraph VER["verification/"]
            ST["state.py\nAlertState TypedDict · ProbeRecord"]
            ND["nodes.py\nprobe_generator · runtime_executor\nresponse_evaluator · retry_evaluator\nbuild_local_probe_url"]
            WF["workflow.py\niter_verification_states (async)"]
            PROF["profile.py\nload_target_profile"]
            VSTORE["verification_store.py\nsave/load/clear confirmed results"]
        end

        CLF["classifier/classifier.py\nclassify · apply_classification\nsort_findings · calculate_issue_risk_score"]

        subgraph CI["code_intelligence/"]
            SR["shadow_ranker.py\nGraphCodeBERTShadowRanker\nroute_candidate_id"]
            AS["assessment_schema.py"]
        end

        subgraph PLAN["dast_planner/"]
            PL["planner.py\nbuild_scan_plan\nScanPlan · ScanTask"]
        end

        subgraph SM["scan_manager/"]
            JOBS["jobs.py\nscan_jobs · ScanAlreadyRunning"]
            HIST["history.py\ncompare_finding_snapshots"]
            COORD["coordinator.py\nbuild_scan_state · apply_task_update"]
            EVT["event_store.py"]
            STATE["state.py\nScanState"]
        end

        subgraph PCH["patch_engine/"]
            LP["llm_patcher.py\ngenerate_patch · apply_unified_diff\nPatchResult · PatchGenerationError"]
            TP["templates.py\nPATCH_TEMPLATES"]
        end

        subgraph CMP["compliance/"]
            RC["risk_calculator.py\ncalculate_inr_exposure"]
            CM["mapping.py\nmap_finding_to_frameworks\nFRAMEWORK_ORDER"]
        end
    end

    MAIN --> GRAPH & PL & SM & VER & PCH & CMP
    GRAPH --> SP & ZP & CORR & DEDUP & CG & MG & CLF & VSTORE & PROF
    SP & ZP & CORR & DEDUP & MG --> SCHEMA
    CG --> ADAPT & SD & RS
    ADAPT --> RS
    WF --> ST & ND
    ND --> PROF
    PL --> SR & RS
    SR --> AS
    JOBS --> COORD & EVT & STATE
    CM --> RC

    subgraph FRONTEND["frontend/src/"]
        APP["App.tsx"]
        CGRAPH["CorrelationGraph.tsx\n@xyflow/react · elkjs"]
        FDP["FindingDetailPanel.tsx"]
        BRP["BusinessRiskPanel.tsx"]
        PP["PlannerPanel.tsx"]
        HOOK["hooks/useVerification.ts\nSSE EventSource"]
    end

    APP --> CGRAPH & FDP & BRP & PP
    FDP --> HOOK
```

---

*Architecture version: 2.0 — Mitigata Hackathon Problem 06 (Flagship)*
*All diagrams use Mermaid — renders natively in GitHub, GitLab, VS Code (Markdown Preview Enhanced), and Obsidian*
*References: [P06-PRD.md](P06-PRD.md) · [P06-SAST-DAST-Correlation-Engine.md](P06-SAST-DAST-Correlation-Engine.md) · [P06-Build-Plan.md](P06-Build-Plan.md)*
