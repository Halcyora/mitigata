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

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         Mitigata Pipeline                                    │
│                                                                              │
│  Semgrep (SAST)  ──►  UnifiedFinding[]  ──►  Three-pass AST Route Mapper    │
│  OWASP ZAP (DAST)──►  UnifiedFinding[]  ──►  Deduplication                  │
│                                         ──►  Correlation Gate                │
│                                               (target + CWE + route +        │
│                                                scope + parameter)            │
│                                         ──►  Classifier                      │
│                                               Confirmed / Code only /        │
│                                               Runtime only                   │
│                                         ──►  React UI (Correlation           │
│                                               Workbench)                     │
└──────────────────────────────────────────────────────────────────────────────┘
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
    participant FE as Frontend :3000
    participant E as Engine :8000
    participant DC as Docker (internal)

    B->>FE: GET http://localhost:3000
    FE->>E: GET /api/graph?target_id=flask_demo|juice_shop

    Note over E: Ingestion (FR-1, FR-2, FR-3)
    E->>E: semgrep_parser → UnifiedFinding[] (sast, label=Code only)
    E->>E: zap_parser → UnifiedFinding[] (dast, label=Runtime only)
    E->>E: deduplicate_findings (SAST by target/CWE/location; DAST by target/CWE/rule/surface)

    Note over E: Three-Pass AST Route Mapper (FR-4)
    E->>E: select Flask or Express adapter by target profile
    E->>E: Pass 1: decorators/mounts → normalized RouteNode[]
    E->>E: Pass 2: handler + one-hop helper scopes → CodeScope[]
    E->>E: Pass 3: request parameter reads → ParameterRead[]

    Note over E: DAST Planning
    E->>E: build_scan_plan → ScanPlan (targeted + broad ScanTask queue)
    E->>E: advisory GraphCodeBERT ranking (GRAPHCODEBERT_MODE=ON only)

    Note over E: Correlation (FR-5, FR-6)
    E->>E: enrich_findings_with_ast (reachability)
    E->>E: correlate_and_merge: target+CWE+route+scope+parameter → Confirmed
    E->>E: apply persisted verification results
    E->>E: sort_findings: Confirmed → Corroborated → Code only → Runtime only

    Note over E: Graph Build
    E->>E: ELK seed positions → GraphNode[] + GraphEdge[]
    E->>E: GraphStats: total, confirmed, code_only, runtime_only, suppression_ratio
    E-->>FE: GraphResponse {nodes, edges, stats}
    FE-->>B: Correlation Workbench rendered ≤ 3 s
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
    OUT["ComplianceReport\n{financial_risk, compliance,\nframeworks_covered, inc06_ref}"]
```

### 4.8 FastAPI Engine Layer — FR-10

```mermaid
graph LR
    subgraph API["FastAPI Engine — http://localhost:8000"]
        G["GET /api/graph\nfull correlation graph\n≤10s · ELK layout"]
        V["POST /api/verify/{id}\nruntime verifier probe\nSSE stream"]
        VS["GET /api/verify/{id}/stream\nSSE for EventSource"]
        P["POST /api/patch/{id}\ngenerate patch\nSarvam GLM-5.3 → template"]
        PA["POST /api/patch/{id}/apply\napply + re-verify"]
        C["GET /api/compliance/{id}\nINR + 4 frameworks"]
        F["GET /api/findings\nall findings sorted\nConfirmed first"]
        FI["GET /api/findings/{id}\nsingle finding detail\nFR-8: full detail"]
        SAR["GET /api/export/sarif\nB-6: SARIF export\nCI fail on HIGH"]
        H["GET /health\nDocker healthcheck"]
        D["GET /docs\nSwagger UI auto-gen"]
    end

    subgraph MODULES["Engine Modules"]
        ING["ingestion/\nsemgrep_parser\nzap_parser\ncorrelator"]
        AST["ast_mapper/\nroute_extractor\nsink_detector\ncall_graph · merger"]
        LGM["verification/\nstate · nodes · graph"]
        CLF["classifier/\nclassifier"]
        PCH["patch_engine/\nllm_patcher · templates\npatcher"]
        CMP["compliance/\nrisk_calculator · mapping"]
    end

    G --> ING & AST
    V --> LGM
    P --> PCH
    C --> CMP
    F & FI --> CLF
    SAR --> ING
```

### 4.9 React Frontend — FR-8, FR-9

```mermaid
graph TD
    subgraph APP["App.tsx — http://localhost:3000"]
        TS["TargetSelector\nflask_demo | juice_shop"]
        SB["StatsBar · active target_id\ntotal · confirmed · code_only\nruntime_only · suppression_ratio\ncwe_types_covered (Obj 01 proof)"]

        subgraph LEFT["60% Left Panel"]
            CG["CorrelationGraph.tsx\nReact Flow canvas\nELK auto-layout\nConfirmed nodes first\nanimated edges for Confirmed"]
            NT["Node Types\nEndpointNode — HTTP route\nControllerNode — handler fn\nSinkNode — vulnerable line\nEvidenceNode — HTTP proof\nSuppressedNode — dead code grey"]
        end

        subgraph RIGHT["40% Right Panel"]
            DP["FindingDetailPanel.tsx\nFR-8: URL+param+payload\nfile+line+CWE+snippet"]
            LB["LabelBadge\n🔴/🟡/🟠 + confidence %"]
            CS["CodeSnippet\nsyntax highlighted\nline number marker"]
            HT["HttpTrace\nrequest + response evidence"]
            VB["VerifyButton → B-1\nuseVerification() hook\nSSE stream → live flip"]
            PH["ProbeHistory\nexpandable audit log\nshows retry attempts"]
            RB["RemediateButton → B-4\nDiffPreview unified diff\nApplyButton\nVerificationStatus ✅/❌"]
        end

        subgraph RISK["Business Risk Tab"]
            FR["FinancialRisk\n₹ exposure · breach prob %"]
            CT["ComplianceTable\nRBI / SEBI / ISO / DPDP rows"]
            CI["CyberInsuranceFlag\nYES/NO badge"]
            IR["Inc06Reference\n2017 Credit Bureau callout"]
        end
    end

    TS --> SB
    SB --> LEFT
    SB --> RIGHT
    CG --> DP
    DP --> LB & CS & HT & VB & RB
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
        X["curl :5050 ❌"]
    end

    subgraph PUB["Docker Network: public"]
        FE["mitigata-frontend\n:3000"]
        ENG["mitigata-engine\n:8000"]
    end

    subgraph INT["Docker Network: internal\ninternal: true"]
        FLASK["Flask target\nwe45/Vulnerable-Flask-App\nNOT on public network"]
        JUICE["Juice Shop target\nOWASP Juice Shop · Express\nNOT on public network"]
    end

    B --> FE
    C --> ENG
    X -. "connection refused" .-> FLASK
    X -. "connection refused" .-> JUICE
    FE <--> ENG
    ENG -->|"profile-selected probes\ninternal network only"| FLASK
    ENG -->|"profile-selected probes\ninternal network only"| JUICE

    style INT fill:#2d1515,color:#fff
    style X fill:#dc2626,color:#fff
```

**Probe route:** `engine (internal) → selected target (internal)` — never leaves Docker network. Target profile selection determines both the target origin and the matching read-only source mount; the engine must not fall back to an arbitrary host or combine results across profiles.

---

## 6. Data Schemas

### 6.1 UnifiedFinding — FR-3 Common Format

```mermaid
classDiagram
    class UnifiedFinding {
        +str id  UUID auto-generated
        +str target_id  flask_demo | juice_shop
        +str source  sast | dast
        +str cwe_id  MANDATORY CWE-89 etc
        +str label  Confirmed | Code only | Runtime only
        +str file  app/app.py
        +int line  47
        +str function  login
        +str sink_type  sql_injection
        +str url  selected target origin + path
        +str method  POST
        +str parameter  username
        +str evidence  Response contained 49
        +int http_status  200
        +str rule_id  semgrep rule id
        +str severity  HIGH | MEDIUM | LOW
        +bool reachable  set by AST mapper
        +list routes  routes reaching this sink
        +list merged_from  FR-6 dedup tracking
        +float confidence  0.0 to 1.0
    }
```

### 6.2 RouteNode — FR-4 Route Mapping

```mermaid
classDiagram
    class RouteNode {
        +str target_id
        +str normalized_url
        +str original_path
        +list methods
        +str handler
        +CodeScope[] scopes
        +ParameterRead[] input_parameters
        +matches_path(path) bool
        +contains_location(file, line) bool
    }

    class CodeScope {
        +str file
        +int start_line
        +int end_line
        +str function
    }

    class ParameterRead {
        +str name
        +str source
    }

    RouteNode "1" --> "1..*" CodeScope : handler and direct callees
    RouteNode "1" --> "0..*" ParameterRead : observed request inputs
```

### 6.3 AlertState — runtime verifier

```mermaid
classDiagram
    class AlertState {
        +str finding_id
        +str target_id
        +str target_origin  configured local profile origin
        +str route  /login
        +str method  POST
        +str parameter  username
        +str sink_type  sql_injection
        +str probe_payload  OR 1=1
        +int probe_variant  0=primary 1=retry
        +int http_status
        +str http_response  first 500 chars
        +str evidence  signals found
        +str label  Confirmed | Code only | UNVERIFIED
        +str error  timeout | network error
        +list probe_history  audit log for UI
    }

    class ProbeRecord {
        +int variant
        +str payload
        +int status
        +str response_preview  first 200 chars
    }

    AlertState "1" --> "0..*" ProbeRecord : probe_history
```

### 6.4 GraphResponse — API

```mermaid
classDiagram
    class GraphResponse {
        +str target_id  selected profile
        +list nodes
        +list edges
        +GraphStats stats
    }

    class GraphNode {
        +str id
        +str type  endpoint|controller|sink|evidence|suppressed
        +Position position  ELK pre-computed x y
        +NodeData data
    }

    class NodeData {
        +str label
        +str target_id
        +str finding_label  Confirmed | Code only | Runtime only
        +float confidence
        +str file
        +int line
        +str cwe
        +str evidence
    }

    class GraphEdge {
        +str id
        +str source
        +str target
        +bool animated  true for Confirmed
    }

    class GraphStats {
        +int total
        +int confirmed
        +int code_only
        +int runtime_only
        +float suppression_ratio
        +list cwe_types_covered  Obj 01 proof
    }

    GraphResponse "1" --> "0..*" GraphNode : nodes
    GraphResponse "1" --> "0..*" GraphEdge : edges
    GraphResponse "1" --> "1" GraphStats : stats
    GraphNode "1" --> "1" NodeData : data
```

---

## 7. API Contract

```mermaid
graph LR
    subgraph ENDPOINTS["FastAPI Endpoints"]
        E1["GET /api/graph?target_id=...\nprofile-scoped · ≤10s · cached 10s TTL"]
        E2["POST /api/verify/{id}\nfinding target_id selects profile\nSSE stream · ≤2s/probe"]
        E3["GET /api/verify/{id}/stream\nEventSource endpoint"]
        E4["POST /api/patch/{id}\nselected-target source · ≤15s"]
        E5["POST /api/patch/{id}/apply\nprofile-scoped git apply + re-verify"]
        E6["GET /api/compliance/{id}\n<200ms · dict lookup"]
        E7["GET /api/findings?target_id=...\nprofile-scoped · Confirmed first"]
        E8["GET /api/findings/{id}\nFR-8 detail includes target_id"]
        E9["GET /api/export/sarif\nB-6 SARIF export"]
        E10["GET /health\nDocker healthcheck"]
        E11["GET /docs\nSwagger UI"]
    end
```

**SSE Event Format:**
```json
// Intermediate:
{"label": "Code only", "probe_history": [...], "done": false}
// Final:
{"label": "Confirmed", "evidence": "['49']", "probe_history": [...], "done": true}
```

---

## 8. Answer Key Mapping

How our architecture maps to the 36 planted vulnerabilities judges score against:

```mermaid
graph TD
    subgraph AK["Flask fixture answer key (36 planted)"]
        P20["20 Code+Runtime Pairs\nConfirmed candidates"]
        P10["10 Code only\ne.g. hardcoded secrets"]
        P6["6 Runtime only\ne.g. missing headers"]
        P8["~8 Safe Decoys\nparameterised queries\nshould NOT be reported"]
    end

    subgraph HOW["How We Hit Each"]
        H20["target_id + CWE + normalized route\n+ method/source when known\n+ code scope + attacked parameter\n→ Confirmed label"]
        H10["SAST only, no DAST match\n→ Code only label\nFR-7 classification"]
        H6["DAST only, no SAST match\n→ Runtime only label\nFR-7 classification"]
        H8["AST reachability check\nparameterised query detection\nB-2 noise cut\nNOT reported"]
    end

    subgraph TARGETS["Performance Targets"]
        T1["Correct links > 50% Good\n> 80% Great\nreport metrics per target profile"]
        T2["Wrong links < 20% Good\n< 5% Great\nAST gates false merges"]
        T3["False alarms < 30% Good\n< 10% Great\nB-2 suppresses safe decoys"]
        T4["Code detection > 60% Good\n> 85% Great\nSemgrep multi-config"]
        T5["Runtime detection > 50% Good\n> 80% Great\nZAP all 30 routes"]
    end

    P20 --> H20 --> T1
    P10 --> H10 --> T2
    P6 --> H6 --> T3
    P8 --> H8 --> T3
    H20 --> T4
    H20 --> T5
```

---

## 9. Performance Budget

```mermaid
gantt
    title Operation Timing Budget
    dateFormat  X
    axisFormat  %ss

    section Startup
    docker compose up --build    :0, 60
    Target healthcheck           :0, 30

    section API (cold)
    GET /api/graph (cold)        :crit, 0, 10
    GET /api/graph (warm/cached) :0, 1

    section runtime verifier Probes
    Single probe (hard limit)    :crit, 0, 2
    Probe + retry (2 attempts)   :0, 4

    section UI
    Initial render               :crit, 0, 3
    Node click → detail          :0, 1

    section Patch
    GLM-5.3 patch generation    :0, 10
    Template patch (fallback)    :0, 1
    git apply + re-verify        :0, 3
    Total patch + re-verify      :crit, 0, 15

    section Compliance
    Compliance report            :0, 1
```

| Operation | Budget | Implementation |
|---|---|---|
| `docker compose up --build` | < 60s | cached layers after first run |
| Target healthcheck | < 30s | curl retry 3× with 10s gap |
| `GET /api/graph` (cold) | **≤ 10s** | AST parse + ELK layout |
| `GET /api/graph` (warm) | < 1s | in-memory cache |
| Single runtime verifier probe | **≤ 2s** | `httpx timeout=2.0` |
| Probe + retry | ≤ 4s | 2 × 2s probes |
| UI initial render | **≤ 3s** | pre-computed ELK positions |
| Patch generation (GLM-5.3) | ≤ 10s | 10s timeout on LLM |
| Patch generation (template) | < 50ms | dict lookup |
| Total patch + re-verify | **≤ 15s** | within PRD budget |
| Full scan + report | **< 5 min** | pre-seeded data + targeted probes |

---

## 10. Dependency Graph

```mermaid
graph TD
    subgraph ENGINE["engine/"]
        MAIN["api/main.py\nFastAPI app"]

        subgraph ING["ingestion/"]
            SCHEMA["schema.py\nUnifiedFinding\nPydantic v2"]
            SP["semgrep_parser.py"]
            ZP["zap_parser.py"]
            CORR["correlator.py\ntarget + CWE + route + scope + parameter\nFR-5 FR-6"]
        end

        subgraph AST["ast_mapper/ + adapters/"]
            RS["route_schema.py\nRouteNode · CodeScope · ParameterRead"]
            RE["Flask + Express adapters\nFR-4\nPython ast + Node.js AST"]
            SD["sink_detector.py\nstdlib: ast"]
            CG["call_graph.py\none-hop helper scopes\nrequest parameter reads"]
            MG["merger.py\nAST enrichment"]
        end

        subgraph LGM["verification/"]
            ST["state.py\nAlertState TypedDict"]
            ND["nodes.py\nhttpx, os"]
            GR["workflow.py\nplain async sequence"]
        end

        CLF["classifier/classifier.py\nstdlib only"]

        subgraph PCH["patch_engine/"]
            LP["llm_patcher.py\nopenai, os"]
            TP["templates.py\nstdlib only"]
            PA["patcher.py\nsubprocess, git"]
        end

        subgraph CMP["compliance/"]
            RC["risk_calculator.py\nstdlib only"]
            CM["mapping.py\nstdlib only"]
        end
    end

    MAIN --> SP & ZP & CORR
    MAIN --> CG & MG
    MAIN --> GR
    MAIN --> CLF
    MAIN --> PA
    MAIN --> CM

    SP --> SCHEMA
    ZP --> SCHEMA
    CORR --> SCHEMA
    MG --> SCHEMA
    CG --> RE & SD & RS
    RE --> RS
    GR --> ST & ND
    PA --> LP & TP
    CM --> RC

    subgraph FRONTEND["frontend/src/"]
        APP["App.tsx"]
        CGRAPH["CorrelationGraph.tsx\n@xyflow/react · elkjs"]
        FDP["FindingDetailPanel.tsx"]
        BRP["BusinessRiskPanel.tsx"]
        RTB["ReTestButton.tsx"]
        HOOKS["hooks/\nuseVerification SSE\nusePatch"]
    end

    APP --> CGRAPH & FDP & BRP & RTB
    FDP --> HOOKS
    RTB --> HOOKS

    subgraph DEPS["Python deps"]
        FASTAPI["fastapi · uvicorn"]
        PYDANTIC["pydantic>=2"]
        HTTPX["httpx"]
        PY_DEP["plain Python"]
        OAI["openai (optional)"]
    end

    MAIN --- FASTAPI
    SCHEMA --- PYDANTIC
    ND --- HTTPX
    GR --- PY_DEP
    LP --- OAI
```

**Objective-to-Component Mapping:**

```mermaid
graph LR
    subgraph OBJ["Objectives → Components"]
        O1["Objective 01\nFR-1 FR-2 FR-3"] --> C1["semgrep_parser\nzap_parser\nschema UnifiedFinding"]
        O2["Objective 02\nFR-4 FR-5 FR-6"] --> C2["three-pass Flask/Express route adapters FR-4\nroute-aware DAST planner + GraphCodeBERT ranking\ncorrelator: target + CWE + route + scope + parameter\nmethod/source when available · FR-5 FR-6 dedup"]
        O3["Objective 03\nFR-7 FR-8 FR-9"] --> C3["classifier\nverification B-1\nFindingDetailPanel FR-8\ncorrelator sort FR-9"]
    end
```

---

*Architecture version: 1.5 — Mitigata Hackathon Problem 06 (Flagship); route-aware planner with advisory GraphCodeBERT ranking, bounded verification, and time-budgeted DAST*
*All diagrams use Mermaid — renders natively in GitHub, GitLab, VS Code with Markdown Preview Enhanced, and Obsidian*  
*Reference: [P06-PRD.md](P06-PRD.md) · [P06-SAST-DAST-Correlation-Engine.md](P06-SAST-DAST-Correlation-Engine.md) · [P06-Build-Plan.md](P06-Build-Plan.md)*
