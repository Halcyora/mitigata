# P06 Architecture — SAST & DAST Correlation Engine
## Complete System Design with Full Data Flow

> **Mitigata Hackathon — Problem 06 · Flagship**  
> Three Objectives: Scan Code+App · Correlate+Merge · Prioritise  
> Real Incident: INC-06 — 2017 Credit Bureau Breach (~145M records)  
> Architecture version: 1.0

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Container Architecture](#2-container-architecture)
3. [End-to-End Data Flow](#3-end-to-end-data-flow)
4. [Component Deep-Dives](#4-component-deep-dives)
   - 4.1 [Ingestion Pipeline (Objective 01)](#41-ingestion-pipeline-objective-01)
   - 4.2 [AST Route-to-Sink Mapper (Objective 02)](#42-ast-route-to-sink-mapper-objective-02)
   - 4.3 [Correlation & Merge Engine (Objective 02)](#43-correlation--merge-engine-objective-02)
   - 4.4 [LangGraph Verification Loop (Objective 02+03)](#44-langgraph-verification-loop-objective-0203)
   - 4.5 [3-Label Classifier (Objective 03)](#45-3-label-classifier-objective-03)
   - 4.6 [Patch Engine](#46-patch-engine)
   - 4.7 [Compliance Translator](#47-compliance-translator)
   - 4.8 [FastAPI Engine Layer](#48-fastapi-engine-layer)
   - 4.9 [React Frontend](#49-react-frontend)
5. [Network Topology](#5-network-topology)
6. [Data Schemas](#6-data-schemas)
7. [API Contract](#7-api-contract)
8. [Security Boundaries](#8-security-boundaries)
9. [Performance Budget](#9-performance-budget)
10. [Dependency Graph](#10-dependency-graph)

---

## 1. System Overview

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║              PROBLEM 06 — SAST & DAST CORRELATION ENGINE                        ║
║                                                                                  ║
║  OBJECTIVE 01: Scan Code + App                                                   ║
║  ┌─────────────────────────────────────────────────────────────────────────┐     ║
║  │  Semgrep (SAST)         OWASP ZAP (DAST)                                │     ║
║  │  ├─ CWE-89 (SQLi) ✅    ├─ CWE-89 (SQLi) ✅                            │     ║
║  │  ├─ CWE-79 (XSS)  ✅    ├─ CWE-79 (XSS)  ✅                            │     ║
║  │  ├─ CWE-94 (SSTI)       ├─ CWE-94 (SSTI)                               │     ║
║  │  ├─ CWE-347 (JWT)       └─ CWE-347 (JWT)                               │     ║
║  │  ├─ CWE-502 (Pickle)                                                    │     ║
║  │  └─ CWE-78 (CMDi)                                                       │     ║
║  │            ↓                      ↓                                     │     ║
║  │     UnifiedFinding[]        UnifiedFinding[]   ← one common format      │     ║
║  └─────────────────────────────────────────────────────────────────────────┘     ║
║                              ↓                                                   ║
║  OBJECTIVE 02: Correlate + Merge                                                 ║
║  ┌─────────────────────────────────────────────────────────────────────────┐     ║
║  │  AST Call Graph (Python ast)                                            │     ║
║  │  Route → Controller → Sink (deterministic, no LLM)                     │     ║
║  │                              ↓                                          │     ║
║  │  Correlation & Merge Engine                                             │     ║
║  │  CWE join + route URL match → single merged record per vulnerability    │     ║
║  │                              ↓                                          │     ║
║  │  LangGraph Verification Loop (stateful agent)                           │     ║
║  │  Code only finding → probe → evidence → Confirmed                       │     ║
║  └─────────────────────────────────────────────────────────────────────────┘     ║
║                              ↓                                                   ║
║  OBJECTIVE 03: Prioritise What to Fix                                            ║
║  ┌─────────────────────────────────────────────────────────────────────────┐     ║
║  │  🔴 Confirmed    (Rank 1) — SAST + DAST both match — fix immediately    │     ║
║  │  🟡 Code only   (Rank 2) — SAST only — review / suppress if dead code  │     ║
║  │  🟠 Runtime only (Rank 3) — DAST only — investigate configuration      │     ║
║  │                              ↓                                          │     ║
║  │  Auto-Patch (GPT-4o → template) + Re-verify + Compliance Report        │     ║
║  └─────────────────────────────────────────────────────────────────────────┘     ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

---

## 2. Container Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         HOST MACHINE (Developer / Demo)                         │
│                                                                                 │
│   Browser ──► http://localhost:3000   (Correlation Workbench UI)                │
│   curl    ──► http://localhost:8000   (Engine API + Swagger docs)               │
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                    DOCKER COMPOSE NETWORK                                │   │
│  │                                                                          │   │
│  │  ┌──────────────────────────────────────────────────────────────────┐   │   │
│  │  │                    PUBLIC NETWORK                                 │   │   │
│  │  │                                                                   │   │   │
│  │  │  ┌─────────────────────────┐    ┌──────────────────────────────┐ │   │   │
│  │  │  │   mitigata-frontend     │    │      mitigata-engine         │ │   │   │
│  │  │  │   React + Vite          │    │      FastAPI (Python)        │ │   │   │
│  │  │  │   Port: 3000            │◄──►│      Port: 8000              │ │   │   │
│  │  │  │                         │    │                              │ │   │   │
│  │  │  │  CorrelationGraph.tsx   │    │  /api/graph    (GET)         │ │   │   │
│  │  │  │  FindingDetailPanel.tsx │    │  /api/verify   (POST+SSE)    │ │   │   │
│  │  │  │  BusinessRiskPanel.tsx  │    │  /api/patch    (POST)        │ │   │   │
│  │  │  │  ReTestButton.tsx       │    │  /api/compliance (GET)       │ │   │   │
│  │  │  └─────────────────────────┘    └──────────────┬───────────────┘ │   │   │
│  │  └──────────────────────────────────────────────── │ ───────────────┘   │   │
│  │                                                     │                    │   │
│  │  ┌──────────────────────────────────────────────── │ ───────────────┐   │   │
│  │  │                    INTERNAL NETWORK             │                 │   │   │
│  │  │                    (internal: true)             │                 │   │   │
│  │  │                                                 ▼                 │   │   │
│  │  │                              ┌──────────────────────────────────┐ │   │   │
│  │  │                              │      mitigata-target             │ │   │   │
│  │  │                              │  we45/Vulnerable-Flask-App       │ │   │   │
│  │  │                              │  Port: 5050 (internal only)      │ │   │   │
│  │  │                              │                                  │ │   │   │
│  │  │                              │  Routes:                         │ │   │   │
│  │  │                              │  POST /login       (CWE-347)     │ │   │   │
│  │  │                              │  POST /register/user (CWE-916)   │ │   │   │
│  │  │                              │  POST /fetch/customer (CWE-347)  │ │   │   │
│  │  │                              │  GET  /           (CWE-200)      │ │   │   │
│  │  │                              │  404 handler      (CWE-94)       │ │   │   │
│  │  │                              └──────────────────────────────────┘ │   │   │
│  │  └──────────────────────────────────────────────────────────────────┘   │   │
│  │                                                                          │   │
│  │  Volumes:                                                                │   │
│  │  ./target-app ──► /target-src (read-only) ── engine AST mapper          │   │
│  │  ./data       ──► /app/data              ── pre-seeded scan results      │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘

⚠️  SECURITY: mitigata-target is ONLY reachable from mitigata-engine via
    the internal Docker network. No direct host access. No external probes.
```

---

## 3. End-to-End Data Flow

### 3.1 Full Pipeline — Startup to Classified Findings

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                    FULL DATA FLOW — PROBLEM 06                                   │
│                                                                                  │
│  ① STARTUP (docker compose up --build)                                           │
│  ─────────────────────────────────────                                           │
│  target container starts → healthcheck passes                                    │
│  engine container starts → reads pre-seeded data/semgrep-results.json           │
│                          → reads pre-seeded data/zap-alerts.json                │
│                          → mounts ./target-app as /target-src (read-only)       │
│  frontend container starts → connects to engine at :8000                        │
│                                                                                  │
│  ② INGESTION (Objective 01 — one common format with CWE numbers)                │
│  ─────────────────────────────────────────────────────────────────               │
│  semgrep_parser.py                                                               │
│    reads data/semgrep-results.json                                               │
│    extracts: file, line, rule_id, CWE from metadata                             │
│    outputs: UnifiedFinding(source="sast", cwe_id="CWE-89", ...)                 │
│                                                                                  │
│  zap_parser.py                                                                   │
│    reads data/zap-alerts.json                                                    │
│    extracts: url, method, parameter, evidence, cweid                            │
│    outputs: UnifiedFinding(source="dast", cwe_id="CWE-89", ...)                 │
│                                                                                  │
│  Result: sast_findings[] + dast_findings[]  (both in UnifiedFinding format)     │
│                                                                                  │
│  ③ AST ANALYSIS (Objective 02 — deterministic linkage)                          │
│  ──────────────────────────────────────────────────────                          │
│  route_extractor.py                                                              │
│    walks /target-src/*.py (read-only volume mount)                               │
│    finds: @app.route, @app.post, @app.errorhandler, etc.                        │
│    outputs: routes[] = [{file, function, route, methods, line}]                 │
│                                                                                  │
│  sink_detector.py                                                                │
│    walks each FunctionDef AST node                                               │
│    matches: .execute(tainted), render_template_string, pickle.loads,            │
│             jwt.decode(verify=False), hashlib.md5, eval(), os.popen()           │
│    outputs: sinks[] = [{file, line, sink_type, function}]                       │
│                                                                                  │
│  call_graph.py (BFS)                                                             │
│    for each route handler → BFS through call edges → set of reachable functions │
│    for each sink → check if any route reaches its containing function           │
│    outputs:                                                                      │
│      reachable_sinks[]   → linked to routes (Objective 02 linkage)             │
│      unreachable_sinks[] → dead code (Code only, suppress)                     │
│      stats.suppression_ratio ≥ 0.70                                             │
│                                                                                  │
│  merger.py                                                                       │
│    enriches each SAST finding with: reachable=True/False, routes=[]             │
│                                                                                  │
│  ④ CORRELATION & MERGE (Objective 02 — each vulnerability appears once)         │
│  ───────────────────────────────────────────────────────────────────────         │
│  correlator.py                                                                   │
│    for each SAST finding:                                                        │
│      find DAST findings with same cwe_id                                        │
│      if DAST URL path ∈ SAST finding's routes → MERGE → "Confirmed"            │
│      elif CWE match only → MERGE → "Confirmed" (lower confidence)               │
│      else → keep as "Code only"                                                  │
│    remaining DAST findings → "Runtime only"                                     │
│    sort: Confirmed first, then Code only, then Runtime only                     │
│    outputs: merged_findings[] (deduplicated, labelled, ranked)                  │
│                                                                                  │
│  ⑤ CLASSIFICATION (Objective 03 — label + rank)                                 │
│  ─────────────────────────────────────────────                                   │
│  classifier.py                                                                   │
│    applies classification rules in priority order                                │
│    assigns: label, confidence (0.0–1.0), reason                                 │
│    enforces: Confirmed always rank 1                                             │
│                                                                                  │
│  ⑥ GRAPH BUILD & LAYOUT                                                          │
│  ────────────────────                                                            │
│  engine/api/main.py  GET /api/graph                                             │
│    builds node graph from merged_findings                                        │
│    computes ELK layout (x, y positions)                                         │
│    returns: {nodes[], edges[], stats{}}                                          │
│                                                                                  │
│  ⑦ UI RENDER                                                                     │
│  ───────────                                                                     │
│  React frontend fetches /api/graph                                               │
│  React Flow renders attack path graph                                            │
│  Split-screen: graph (left) | detail panel (right)                              │
│  Confirmed findings rendered first with red badges                               │
│  Stats bar: total · confirmed · suppression_ratio · cwe_types_covered           │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Live Verification Flow (LangGraph — Objective 02+03)

```
User clicks "Verify" on a "Code only" finding
             │
             ▼
POST /api/verify/{finding_id}  (Engine FastAPI)
             │
             ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                    LANGGRAPH STATE MACHINE                                 │
│                                                                            │
│  AlertState {                                                              │
│    finding_id, route, method, parameter, sink_type,                       │
│    probe_payload, probe_variant=0,                                         │
│    label="UNVERIFIED", probe_history=[]                                    │
│  }                                                                         │
│                                                                            │
│  ┌─────────────────┐                                                       │
│  │  probe_generator │  ← selects canary payload by sink_type + variant    │
│  │                  │    e.g. sink="ssti" → payload="{{7*7}}"             │
│  └────────┬─────────┘                                                      │
│           │  state.probe_payload = "{{7*7}}"                              │
│           ▼                                                                │
│  ┌─────────────────┐                                                       │
│  │ runtime_executor │  ← fires HTTP probe at mitigata-target:5050         │
│  │                  │    via internal Docker network ONLY                  │
│  │  httpx.request(  │    timeout=2.0s hard limit                          │
│  │    method=POST,  │    records: status, response[:500], probe_history   │
│  │    url=target/   │                                                      │
│  │    route,        │                                                      │
│  │    json={param:  │                                                      │
│  │    payload},     │                                                      │
│  │    timeout=2.0)  │                                                      │
│  └────────┬─────────┘                                                      │
│           │  state.http_response = "...49..." (SSTI evaluated {{7*7}})   │
│           ▼                                                                │
│  ┌──────────────────────┐                                                  │
│  │  response_evaluator  │  ← checks response for EVIDENCE_SIGNALS        │
│  │                      │    ssti signals: ["49", "Jinja2", "{{"]        │
│  │  "49" found in resp  │    found=["49"] → label="Confirmed"            │
│  └────────┬─────────────┘                                                  │
│           │                                                                │
│    ┌──────┴──────────┐                                                     │
│    │                 │                                                     │
│  Evidence          No evidence                                             │
│  found             found                                                   │
│    │                 │                                                     │
│    │             probe_variant==0?                                         │
│    │                 │                                                     │
│    │           ┌─────┴──────┐                                             │
│    │           │            │                                             │
│    │         Yes           No                                             │
│    │           │            │                                             │
│    │    ┌──────────────┐   END (Code only)                                │
│    │    │retry_evaluator│                                                  │
│    │    │ variant += 1  │                                                  │
│    │    └──────┬────────┘                                                  │
│    │           │ loops back to probe_generator                             │
│    │           │ with variant payload "${7*7}"                             │
│    │           ▼ (second attempt)                                          │
│    │    [probe_generator → runtime_executor → response_evaluator]         │
│    │                                                                       │
│    ▼                                                                       │
│  label = "Confirmed"                                                       │
│  evidence = "Response contained: ['49']"                                   │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
             │
             ▼
SSE stream → frontend EventSource
             │
             ▼
Label badge flips: 🟡 "Code only" → 🔴 "Confirmed" (live in UI)
Finding re-sorted to Rank 1 position
probe_history panel shows both probe attempts
```

### 3.3 Auto-Remediation Flow

```
User clicks "Auto-Remediate" on a Confirmed finding
             │
             ▼
POST /api/patch/{finding_id}  (Engine FastAPI)
             │
             ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                    PATCH ENGINE                                            │
│                                                                            │
│  1. Read code context from /target-src (read-only volume mount)           │
│     lines [max(0, line-5) : line+5] around the vulnerable sink            │
│                                                                            │
│  2. Try Azure OpenAI GPT-4o (primary)                                     │
│     POST https://{endpoint}/openai/deployments/gpt-4o/chat/completions    │
│     system: "Generate minimal unified diff to fix {sink_type}..."         │
│     user:   "File: {file}, Line: {line}\n```python\n{context}\n```"       │
│     timeout: 10s                                                           │
│     ↓                                                                      │
│     If response starts with "---" or "@@" → valid diff → use it          │
│                                                                            │
│  3. Try Azure OpenAI GPT-4o-mini (fallback)                               │
│     Same prompt, faster/cheaper model                                      │
│                                                                            │
│  4. Deterministic template patch (zero-cost fallback)                     │
│     PATCH_TEMPLATES["sql_injection"] → hardcoded parameterised query fix  │
│     Demo never breaks regardless of Azure availability                    │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
             │
             ▼  patch_result = {patch: "--- a/app.py\n+++ ...", source: "llm_gpt4o"}
             │
             ▼
UI shows Git diff preview (unified diff format)
             │
User clicks "Apply"
             │
             ▼
POST /api/patch/{finding_id}/apply
             │
             ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  git apply --check {patch_file}   ← dry-run validation first              │
│  git apply {patch_file}           ← apply to /target-src                  │
│  (target container auto-reloads if Flask debug=True)                      │
└────────────────────────────────────────────────────────────────────────────┘
             │
             ▼
RE-VERIFICATION: same LangGraph probe fires again
             │
             ├─► Probe blocked (no evidence signals) → ✅ "Fix Verified"
             └─► Probe succeeds (evidence found)     → ❌ "Fix Insufficient"
```

---

## 4. Component Deep-Dives

### 4.1 Ingestion Pipeline (Objective 01)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    INGESTION PIPELINE                                        │
│                    (Objective 01: one common format, CWE numbers)            │
│                                                                              │
│  INPUT A: data/semgrep-results.json                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  {                                                                   │    │
│  │    "results": [{                                                     │    │
│  │      "check_id": "python.flask.security.audit.render-template-string"│    │
│  │      "path": "app/app.py",                                          │    │
│  │      "start": {"line": 89},                                         │    │
│  │      "extra": {                                                      │    │
│  │        "severity": "ERROR",                                         │    │
│  │        "metadata": {"cwe": ["CWE-94: Improper Neutralization..."]}  │    │
│  │      }                                                               │    │
│  │    }]                                                                │    │
│  │  }                                                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                    │                                                         │
│                    ▼  semgrep_parser.py                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  UnifiedFinding(                                                     │    │
│  │    source="sast",                                                    │    │
│  │    cwe_id="CWE-94",          ← normalised from "CWE-94: Improper..."│    │
│  │    file="app/app.py",                                               │    │
│  │    line=89,                                                          │    │
│  │    rule_id="python.flask.security.audit.render-template-string",    │    │
│  │    severity="ERROR",                                                 │    │
│  │    sink_type="ssti",                                                 │    │
│  │    label="Code only",        ← default, overridden by correlator    │    │
│  │  )                                                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  INPUT B: data/zap-alerts.json                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  {                                                                   │    │
│  │    "alerts": [{                                                      │    │
│  │      "cweid": "94",                                                  │    │
│  │      "url": "http://target:5050/nonexistent",                       │    │
│  │      "method": "GET",                                                │    │
│  │      "param": "url",                                                 │    │
│  │      "evidence": "{{7*7}}",                                         │    │
│  │      "riskdesc": "High (High)"                                       │    │
│  │    }]                                                                │    │
│  │  }                                                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                    │                                                         │
│                    ▼  zap_parser.py                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  UnifiedFinding(                                                     │    │
│  │    source="dast",                                                    │    │
│  │    cwe_id="CWE-94",          ← normalised from cweid: "94"          │    │
│  │    url="http://target:5050/nonexistent",                             │    │
│  │    method="GET",                                                     │    │
│  │    parameter="url",                                                  │    │
│  │    evidence="{{7*7}}",                                               │    │
│  │    severity="HIGH",                                                  │    │
│  │    sink_type="ssti",                                                 │    │
│  │    label="Runtime only",     ← default, overridden by correlator    │    │
│  │  )                                                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  COVERAGE VERIFICATION (Objective 01):                                      │
│  CWE types in corpus: {CWE-89, CWE-79, CWE-94, CWE-347, CWE-502, CWE-78}  │
│  Mandatory: CWE-89 ✅  CWE-79 ✅  (4+ total ✅)                             │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 AST Route-to-Sink Mapper (Objective 02)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    AST ROUTE-TO-SINK MAPPER                                  │
│                    (Objective 02: deterministic linkage, no LLM)             │
│                                                                              │
│  SOURCE: /target-src/app/app.py  (read-only volume mount)                   │
│                                                                              │
│  STEP 1: Parse Python AST                                                   │
│  ─────────────────────────                                                   │
│  tree = ast.parse(open("app/app.py").read())                                │
│                                                                              │
│  STEP 2: Extract route decorators                                           │
│  ─────────────────────────────────                                           │
│                                                                              │
│  app.py (simplified):                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  @app.route('/login', methods=['POST'])     ← ROUTE DECORATOR       │   │
│  │  def login():                               ← HANDLER FUNCTION      │   │
│  │      ...                                                             │   │
│  │      token = jwt.encode(                   ← SINK (CWE-347)         │   │
│  │          payload, app.config['SECRET_KEY_HMAC'])                    │   │
│  │                                                                      │   │
│  │  @app.errorhandler(404)                    ← ROUTE DECORATOR        │   │
│  │  def pnf(e):                               ← HANDLER FUNCTION      │   │
│  │      template = "...%s..." % request.url                            │   │
│  │      return render_template_string(template)  ← SINK (CWE-94)      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  routes = [                                                                 │
│    {function: "login",  route: "/login",       methods: ["POST"]},         │
│    {function: "pnf",    route: "__error_404__", methods: ["GET"]},         │
│    ...                                                                      │
│  ]                                                                          │
│                                                                              │
│  STEP 3: Build call edges                                                   │
│  ──────────────────────────                                                  │
│  call_edges = {                                                             │
│    "login":    {"jwt.encode", "authenticate_user", ...},                   │
│    "pnf":      {"render_template_string"},                                  │
│    ...                                                                      │
│  }                                                                          │
│                                                                              │
│  STEP 4: BFS reachability from each route handler                          │
│  ─────────────────────────────────────────────────                          │
│  reachable_from_login = BFS("login", call_edges)                           │
│    = {"login", "jwt.encode", "authenticate_user", ...}                     │
│                                                                              │
│  STEP 5: Match sinks to reachable functions                                │
│  ──────────────────────────────────────────                                 │
│                                                                              │
│  Sink: render_template_string at app.py:89 in function pnf()               │
│    → pnf() ∈ reachable_from_pnf ✅                                         │
│    → reachable_sinks: [{file: "app.py", line: 89, sink: "ssti",           │
│                          reachable_from_routes: ["__error_404__"]}]        │
│                                                                              │
│  Sink: pickle.loads at dead_code_helpers.py:18 in _legacy_deserialise()   │
│    → _legacy_deserialise() ∉ any route's reachable set                     │
│    → unreachable_sinks: [{file: "dead_code_helpers.py", line: 18, ...}]   │
│                                                                              │
│  STEP 6: Compute suppression ratio                                         │
│  ────────────────────────────────                                           │
│  total = 11, unreachable = 7                                               │
│  suppression_ratio = 7/11 = 0.636  (add 1 more dead fn → 8/12 = 0.667)   │
│                                                                              │
│  CALL GRAPH OUTPUT:                                                         │
│  {                                                                          │
│    "routes": [...],                                                         │
│    "sinks": [/* reachable sinks with routes */],                           │
│    "unreachable_sinks": [/* dead code */],                                 │
│    "stats": {                                                               │
│      "total_sinks": 12,                                                    │
│      "reachable": 4,                                                       │
│      "unreachable": 8,                                                     │
│      "suppression_ratio": 0.667                                            │
│    }                                                                        │
│  }                                                                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.3 Correlation & Merge Engine (Objective 02)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    CORRELATION & MERGE ENGINE                                │
│                    (Objective 02: each vulnerability appears ONCE)           │
│                                                                              │
│  INPUTS:                                                                    │
│  sast_findings = [                                                          │
│    F1: {source=sast, cwe=CWE-94, file=app.py, line=89, routes=["/404"]}   │
│    F2: {source=sast, cwe=CWE-347, file=app.py, line=42, routes=["/login"]}│
│    F3: {source=sast, cwe=CWE-89, file=dead_code.py, line=18, routes=[]}   │
│    F4: {source=sast, cwe=CWE-502, file=dead_code.py, line=24, routes=[]}  │
│  ]                                                                          │
│                                                                              │
│  dast_findings = [                                                          │
│    D1: {source=dast, cwe=CWE-94, url=http://target/nonexistent, param=url}│
│    D2: {source=dast, cwe=CWE-347, url=http://target/login, param=token}   │
│    D3: {source=dast, cwe=CWE-10, url=http://target/, param=null}          │
│  ]                                                                          │
│                                                                              │
│  MERGE ALGORITHM:                                                           │
│  ─────────────────                                                          │
│                                                                              │
│  F1 (CWE-94):                                                               │
│    dast_by_cwe["CWE-94"] = [D1]                                            │
│    D1.url="/nonexistent" ∩ F1.routes=["/404"] → no path match              │
│    but CWE matches → MERGE F1+D1 → label="Confirmed" (confidence=0.80)    │
│    merged_from=[F1.id, D1.id]                                              │
│    D1 consumed ✓                                                            │
│                                                                              │
│  F2 (CWE-347):                                                              │
│    dast_by_cwe["CWE-347"] = [D2]                                           │
│    D2.url="/login" ∈ F2.routes=["/login"] → route match ✅                 │
│    MERGE F2+D2 → label="Confirmed" (confidence=0.95, dual_confirmed=True) │
│    merged_from=[F2.id, D2.id]                                              │
│    D2 consumed ✓                                                            │
│                                                                              │
│  F3 (CWE-89, dead code):                                                   │
│    dast_by_cwe["CWE-89"] = []  (ZAP didn't find SQLi)                     │
│    No DAST match → label="Code only" (unreachable, will be suppressed)    │
│                                                                              │
│  F4 (CWE-502, dead code):                                                  │
│    No DAST match → label="Code only" (unreachable, suppressed)            │
│                                                                              │
│  D3 (CWE-10, DAST only):                                                   │
│    Not consumed by any SAST finding → label="Runtime only"                 │
│                                                                              │
│  OUTPUT (sorted: Confirmed first):                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Rank 1: 🔴 Confirmed  — CWE-347 (JWT) — app.py:42 — /login        │   │
│  │          merged_from=[F2.id, D2.id]  confidence=0.95               │   │
│  │          code_location={file:app.py, line:42}                       │   │
│  │          runtime_proof={url:/login, method:POST, param:token}       │   │
│  │                                                                      │   │
│  │  Rank 1: 🔴 Confirmed  — CWE-94 (SSTI) — app.py:89 — /404         │   │
│  │          merged_from=[F1.id, D1.id]  confidence=0.80               │   │
│  │          code_location={file:app.py, line:89}                       │   │
│  │          runtime_proof={url:/nonexistent, param:url}                │   │
│  │                                                                      │   │
│  │  Rank 2: 🟡 Code only  — CWE-89 (SQLi) — dead_code.py:18          │   │
│  │          reachable=False  (suppressed — dead code)                  │   │
│  │                                                                      │   │
│  │  Rank 2: 🟡 Code only  — CWE-502 (Pickle) — dead_code.py:24       │   │
│  │          reachable=False  (suppressed — dead code)                  │   │
│  │                                                                      │   │
│  │  Rank 3: 🟠 Runtime only — CWE-10 (config) — http://target/        │   │
│  │          No code sink found                                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  DEDUPLICATION: 4 SAST + 3 DAST = 7 raw findings → 5 merged (2 consumed)  │
│  Each real vulnerability appears EXACTLY ONCE ✅                            │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.4 LangGraph Verification Loop (Objective 02+03)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    LANGGRAPH STATE MACHINE                                   │
│                    (Objective 02+03: live label flip)                        │
│                                                                              │
│  StateGraph(AlertState)                                                     │
│                                                                              │
│  Nodes:                                                                     │
│  ┌──────────────────┐                                                       │
│  │ probe_generator  │  Selects canary payload from CANARY_PAYLOADS dict    │
│  │                  │  by sink_type + probe_variant (0=primary, 1=retry)   │
│  │  Payloads:       │                                                       │
│  │  sql_injection   │  ["' OR '1'='1", "' OR 1=1--"]                       │
│  │  xss             │  ["<script>alert(1)</script>", "<img...>"]           │
│  │  ssti            │  ["{{7*7}}", "${7*7}"]                               │
│  │  jwt_weak_secret │  [crafted JWT signed with "secret"]                  │
│  │  command_injection│ ["; echo CANARY_MITIGATA_2026"]                     │
│  └────────┬─────────┘                                                       │
│           │                                                                  │
│           ▼                                                                  │
│  ┌──────────────────┐                                                       │
│  │ runtime_executor │  httpx.request() to http://target:5050{route}        │
│  │                  │  timeout=2.0s (HARD LIMIT — never blocks demo)       │
│  │  Internal Docker │  records: status, response[:500], probe_history      │
│  │  network ONLY    │  on TimeoutException → label="Code only", continue   │
│  └────────┬─────────┘                                                       │
│           │                                                                  │
│           ▼                                                                  │
│  ┌──────────────────────┐                                                   │
│  │  response_evaluator  │  checks response text for EVIDENCE_SIGNALS       │
│  │                      │  per sink_type                                   │
│  │  sql_injection:  ["OperationalError", "sqlite3", "OR '1'='1"]          │
│  │  ssti:           ["49", "Jinja2", "TemplateError"]                      │
│  │  xss:            ["<script>", "alert(1)", "onerror"]                   │
│  │  jwt_weak_secret: ["Authenticated", "admin", "User"]                   │
│  │                                                                          │
│  │  found signals → label="Confirmed"                                      │
│  │  no signals    → label="Code only"                                      │
│  └────────┬─────────────┘                                                   │
│           │                                                                  │
│    ┌──────┴──────────┐                                                      │
│    │                 │  should_retry() conditional edge                    │
│  "Confirmed"    "Code only"                                                 │
│    │             AND probe_variant==0                                       │
│    │                 │                                                      │
│    │           ┌─────┴──────┐                                              │
│    │           │            │                                              │
│    │         Yes           No                                              │
│    │           │            │                                              │
│    │    ┌──────────────┐   END                                             │
│    │    │retry_evaluator│  (label stays "Code only")                       │
│    │    │ variant += 1  │                                                   │
│    │    └──────┬────────┘                                                   │
│    │           │ loops back                                                 │
│    │           ▼                                                            │
│    │    [probe_generator with variant=1]                                   │
│    │                                                                        │
│    ▼                                                                        │
│   END (label="Confirmed", evidence captured)                               │
│                                                                              │
│  PROBE SAFETY CONSTRAINTS:                                                  │
│  ✅ All payloads are read-only canary strings                               │
│  ✅ No DROP TABLE, no OS wipes, no file writes                              │
│  ✅ Probes only on SAST-flagged routes (no spider)                         │
│  ✅ Internal Docker network only (no external traffic)                     │
│  ✅ 2.0s hard timeout (never blocks demo)                                  │
│  ✅ probe_history records all attempts for UI audit trail                  │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.5 3-Label Classifier (Objective 03)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    3-LABEL CLASSIFIER                                        │
│                    (Objective 03: Confirmed / Code only / Runtime only)      │
│                                                                              │
│  Classification rules (strict priority order):                              │
│                                                                              │
│  Rule 1: LangGraph label="Confirmed" AND dual_confirmed=True               │
│          → label=Confirmed, confidence=0.98                                 │
│          reason="SAST sink + DAST probe both confirmed; CWE and route match"│
│                                                                              │
│  Rule 2: LangGraph label="Confirmed"                                        │
│          → label=Confirmed, confidence=0.90                                 │
│          reason="Runtime probe confirmed exploitation evidence"              │
│                                                                              │
│  Rule 3: is_config_only=True (no code sink, DAST only)                     │
│          → label=Runtime only, confidence=0.85                              │
│          reason="Runtime misconfiguration only (headers/CORS/TLS)"         │
│                                                                              │
│  Rule 4: ast_reachable=False (dead code, no route leads here)              │
│          → label=Code only, confidence=0.95                                 │
│          reason="Dead code — no HTTP route leads to this function"          │
│                                                                              │
│  Rule 5: ast_reachable=True (reachable but probe inconclusive)             │
│          → label=Code only, confidence=0.70                                 │
│          reason="Route exposed, leads to sink, probe inconclusive"          │
│                                                                              │
│  Rule 6: ast_reachable=None (unknown)                                       │
│          → label=Code only, confidence=0.50                                 │
│          reason="AST reachability unknown; conservative assignment"         │
│                                                                              │
│  RANKING (Objective 03 hard requirement):                                   │
│  Confirmed    → Rank 1 (always first in UI, API, exports)                  │
│  Code only    → Rank 2                                                      │
│  Runtime only → Rank 3                                                      │
│                                                                              │
│  SUPPRESSION:                                                               │
│  Code only + reachable=False → suppressed in default view                  │
│  Still accessible via "Show suppressed" toggle                              │
│  suppression_ratio = suppressed_count / total_sast_count                   │
│  Target: ≥ 0.70                                                             │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.6 Patch Engine

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    PATCH ENGINE                                              │
│                                                                              │
│  Input: finding (Confirmed label, sink_type, file, line)                   │
│                                                                              │
│  Fallback Chain:                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  1. Azure OpenAI GPT-4o (primary)                                   │   │
│  │     endpoint: AZURE_OPENAI_ENDPOINT                                 │   │
│  │     model: AZURE_OPENAI_DEPLOYMENT (default: gpt-4o)               │   │
│  │     timeout: 10s                                                    │   │
│  │     temperature: 0 (deterministic output)                           │   │
│  │     → returns unified diff starting with "---" or "@@"             │   │
│  │                                                                     │   │
│  │  2. Azure OpenAI GPT-4o-mini (fallback)                            │   │
│  │     model: AZURE_OPENAI_FALLBACK_DEPLOYMENT (gpt-4o-mini)          │   │
│  │     same prompt, faster/cheaper                                     │   │
│  │                                                                     │   │
│  │  3. Deterministic template patch (zero-cost, always available)     │   │
│  │     PATCH_TEMPLATES["sql_injection"] → parameterised query         │   │
│  │     PATCH_TEMPLATES["ssti"]          → render_template() fix       │   │
│  │     PATCH_TEMPLATES["jwt_weak_secret"] → env-based secret          │   │
│  │     PATCH_TEMPLATES["weak_hash"]     → bcrypt replacement          │   │
│  │     PATCH_TEMPLATES["xss"]           → markupsafe.escape           │   │
│  │     PATCH_TEMPLATES["command_injection"] → subprocess list args    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Apply Flow:                                                                │
│  git apply --check {patch}  ← dry-run validation                           │
│  git apply {patch}          ← write to /target-src                         │
│  reverify()                 ← same LangGraph probe fires again             │
│    probe blocked → "Fix Verified — Vulnerability Closed" ✅                │
│    probe succeeds → "Fix Insufficient — Re-patch Required" ❌              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.7 Compliance Translator

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    COMPLIANCE TRANSLATOR                                     │
│                                                                              │
│  Input: Confirmed finding with cwe_id, severity                            │
│                                                                              │
│  Financial Risk (IBM 2024 India benchmark):                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  severity=HIGH → breach_probability=65%                             │   │
│  │  records_at_risk=10,000                                             │   │
│  │  cost_per_record=₹5,000 (IBM 2024 India)                           │   │
│  │  total_exposure = 10,000 × ₹5,000 × 0.65 = ₹3,25,00,000          │   │
│  │  cyber_insurance_impact = ₹3.25cr > ₹50L threshold → TRUE         │   │
│  │                                                                     │   │
│  │  INC-06 reference:                                                  │   │
│  │  "2017 Credit Bureau Breach: 145M records"                         │   │
│  │  "Estimated exposure: ₹61,625 crore"                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  Compliance Mapping (CWE-89 example):                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  rbi_csf:    "Annex I §4.2 — Input Validation & Parameterised Queries"│  │
│  │  sebi_cscrf: "Domain 5: Application Security — Input Validation"    │   │
│  │  iso_27001:  "A.8.28 — Secure coding; A.8.25 — Secure dev lifecycle"│   │
│  │  dpdp_2023:  "§8(1) — Reasonable security safeguards"              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  4 Frameworks covered per finding:                                          │
│  ✅ RBI Cyber Security Framework                                            │
│  ✅ SEBI CSCRF                                                              │
│  ✅ ISO 27001:2022 Annex A                                                  │
│  ✅ DPDP Act 2023 (India's data protection law, in force since 2023)       │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.8 FastAPI Engine Layer

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    FASTAPI ENGINE — API CONTRACT                             │
│                    http://localhost:8000                                     │
│                                                                              │
│  GET  /api/graph                                                            │
│    Triggers: ingestion → AST → correlation → classification → ELK layout   │
│    Returns:  GraphResponse {nodes[], edges[], stats{}}                      │
│    Cache:    10s TTL (re-build on demand)                                   │
│    SLA:      ≤ 10 seconds total                                             │
│                                                                              │
│  POST /api/verify/{finding_id}                                              │
│    Triggers: LangGraph verification loop                                    │
│    Returns:  SSE stream (text/event-stream)                                 │
│    Events:   {label, probe_history, done}                                   │
│    SLA:      ≤ 2 seconds per probe                                          │
│                                                                              │
│  GET  /api/verify/{finding_id}/stream                                       │
│    SSE endpoint for EventSource in frontend                                 │
│    Streams: label updates + probe_history in real time                     │
│                                                                              │
│  POST /api/patch/{finding_id}                                               │
│    Triggers: patch engine (GPT-4o → template fallback)                     │
│    Returns:  {patch: "unified diff", source: "llm_gpt4o"|"template"}       │
│    SLA:      ≤ 15 seconds (10s GPT timeout + 5s buffer)                   │
│                                                                              │
│  POST /api/patch/{finding_id}/apply                                         │
│    Applies patch via git apply                                              │
│    Triggers re-verification automatically                                   │
│    Returns:  {success, reverify_result: {label, evidence}}                 │
│                                                                              │
│  GET  /api/compliance/{finding_id}                                          │
│    Returns:  {financial_risk{}, compliance{rbi,sebi,iso,dpdp}, inc06_ref}  │
│                                                                              │
│  GET  /health                                                               │
│    Returns:  {status: "ok", target_reachable: bool}                        │
│    Used by:  Docker health check                                            │
│                                                                              │
│  GET  /docs                                                                 │
│    Swagger UI (FastAPI auto-generated)                                      │
│    Judges can explore API without frontend                                  │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.9 React Frontend

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    REACT FRONTEND — COMPONENT TREE                          │
│                    http://localhost:3000                                     │
│                                                                              │
│  App.tsx                                                                    │
│  ├── StatsBar                                                               │
│  │   ├── total findings count                                               │
│  │   ├── confirmed count (red badge)                                        │
│  │   ├── code_only count (yellow badge)                                     │
│  │   ├── runtime_only count (orange badge)                                  │
│  │   ├── suppression_ratio % (green if ≥70%)                               │
│  │   └── cwe_types_covered[] (Objective 01 proof)                          │
│  │                                                                          │
│  ├── CorrelationGraph.tsx  (60% left panel)                                │
│  │   ├── React Flow canvas (zoom/pan/click)                                │
│  │   ├── ELK auto-layout (hierarchical, top-to-bottom)                     │
│  │   ├── Node types:                                                        │
│  │   │   ├── EndpointNode   (HTTP route)        — border by label colour   │
│  │   │   ├── ControllerNode (handler function)  — border by label colour   │
│  │   │   ├── SinkNode       (vulnerable line)   — filled by label colour   │
│  │   │   ├── EvidenceNode   (HTTP proof)        — filled by label colour   │
│  │   │   └── SuppressedNode (dead code)         — grey, collapsed          │
│  │   ├── Edges:                                                             │
│  │   │   ├── animated=true for Confirmed paths                             │
│  │   │   └── dashed for Code only paths                                    │
│  │   └── Confirmed nodes always rendered at top of canvas                 │
│  │                                                                          │
│  └── FindingDetailPanel.tsx  (40% right panel)                             │
│      ├── LabelBadge (🔴/🟡/🟠 with confidence %)                          │
│      ├── CodeSnippet (file:line with syntax highlight)                     │
│      ├── HttpTrace (request + response evidence)                            │
│      ├── CweReference (CWE number + description)                           │
│      ├── VerifyButton → useVerification() hook → SSE stream                │
│      │   └── ProbeHistory (expandable — shows retry attempts)              │
│      ├── RemediateButton → usePatch() hook                                 │
│      │   ├── DiffPreview (unified diff with syntax highlight)              │
│      │   ├── ApplyButton → POST /api/patch/{id}/apply                      │
│      │   └── VerificationStatus (✅/❌ live update)                        │
│      └── BusinessRiskTab                                                   │
│          ├── FinancialRisk (₹ exposure, breach probability %)              │
│          ├── ComplianceTable (RBI / SEBI / ISO / DPDP rows)               │
│          ├── CyberInsuranceFlag (YES/NO badge)                             │
│          └── Inc06Reference ("2017 Credit Bureau Breach" callout)         │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Network Topology

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    DOCKER NETWORK TOPOLOGY                                   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  HOST MACHINE                                                        │   │
│  │                                                                      │   │
│  │  Browser → :3000 ──────────────────────────────────────────────┐   │   │
│  │  curl    → :8000 ──────────────────────────────────────────┐   │   │   │
│  │  curl    → :5050 ──── BLOCKED ✗ (internal network)         │   │   │   │
│  │                                                             │   │   │   │
│  └─────────────────────────────────────────────────────────── │ ─ │ ──┘   │
│                                                                │   │       │
│  ┌─────────────────────────────────────────────────────────── │ ─ │ ──┐   │
│  │  PUBLIC NETWORK (docker network: public)                   │   │   │   │
│  │                                                             │   │   │   │
│  │  ┌──────────────────────────────────────────┐             │   │   │   │
│  │  │  mitigata-frontend  :3000                │◄────────────┘   │   │   │
│  │  │  serves React app                        │                 │   │   │
│  │  │  proxies /api/* → engine:8000            │─────────────────┤   │   │
│  │  └──────────────────────────────────────────┘                 │   │   │
│  │                                                                │   │   │
│  │  ┌──────────────────────────────────────────┐                 │   │   │
│  │  │  mitigata-engine    :8000                │◄────────────────┘   │   │
│  │  │  FastAPI app                             │◄────────────────────┘   │
│  │  │  reads /target-src (volume)              │                         │
│  │  │  reads /app/data   (volume)              │                         │
│  │  └──────────────────────────────────────────┘                         │
│  │                              │                                         │
│  └────────────────────────────── │ ──────────────────────────────────────┘   │
│                                  │                                            │
│  ┌─────────────────────────────── │ ──────────────────────────────────────┐  │
│  │  INTERNAL NETWORK (docker network: internal, internal: true)           │  │
│  │                                │                                       │  │
│  │                                ▼                                       │  │
│  │  ┌──────────────────────────────────────────────────────────────┐     │  │
│  │  │  mitigata-target    :5050  (NOT exposed to host)             │     │  │
│  │  │  we45/Vulnerable-Flask-App                                   │     │  │
│  │  │  only reachable from engine via http://target:5050           │     │  │
│  │  └──────────────────────────────────────────────────────────────┘     │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  PROBE SECURITY:                                                            │
│  All LangGraph probes: engine → http://target:5050{route}                  │
│  Route: engine internal network → target internal network                  │
│  No probe ever leaves the Docker network ✅                                 │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Data Schemas

### 6.1 UnifiedFinding (Pydantic v2)

```
UnifiedFinding
├── id:           str        (UUID, auto-generated)
├── source:       "sast"|"dast"
├── cwe_id:       str        (MANDATORY — "CWE-89", "CWE-79", etc.)
├── label:        "Confirmed"|"Code only"|"Runtime only"|null
│
├── [Code location — from SAST + AST mapper]
│   ├── file:     str|null   (e.g. "app/app.py")
│   ├── line:     int|null   (e.g. 47)
│   ├── function: str|null   (e.g. "login")
│   └── sink_type: str|null  (e.g. "sql_injection")
│
├── [Runtime proof — from DAST + LangGraph]
│   ├── url:       str|null  (e.g. "http://target:5050/login")
│   ├── method:    str|null  (e.g. "POST")
│   ├── parameter: str|null  (e.g. "username")
│   ├── evidence:  str|null  (e.g. "Response contained: ['49']")
│   └── http_status: int|null
│
├── [Correlation metadata]
│   ├── rule_id:    str|null  (Semgrep rule ID)
│   ├── severity:   str       (CRITICAL/HIGH/MEDIUM/LOW/INFO)
│   ├── reachable:  bool|null (set by AST mapper)
│   ├── routes:     list[str] (routes that reach this sink)
│   ├── merged_from: list[str] (source finding IDs — Obj 02 dedup)
│   └── confidence: float|null (0.0–1.0)
```

### 6.2 AlertState (LangGraph)

```
AlertState (TypedDict)
├── finding_id:    str
├── route:         str        (e.g. "/login")
├── method:        str        (e.g. "POST")
├── parameter:     str        (e.g. "username")
├── sink_type:     str        (e.g. "sql_injection")
├── probe_payload: str        (e.g. "' OR '1'='1")
├── probe_variant: int        (0=primary, 1=retry)
├── http_status:   int|None
├── http_response: str|None   (first 500 chars)
├── evidence:      str|None   (signals found)
├── label:         "Confirmed"|"Code only"|"Runtime only"|"UNVERIFIED"
├── error:         str|None   (timeout, network error)
└── probe_history: list[dict] (audit log for UI)
    └── [{variant, payload, status, response_preview}]
```

### 6.3 GraphResponse (API)

```
GraphResponse
├── nodes: list[Node]
│   └── Node
│       ├── id:       str
│       ├── type:     "endpoint"|"controller"|"sink"|"evidence"|"suppressed"
│       ├── position: {x: float, y: float}  (ELK pre-computed)
│       └── data
│           ├── label:         str
│           ├── finding_label: "Confirmed"|"Code only"|"Runtime only"|null
│           ├── confidence:    float|null
│           ├── file:          str|null
│           ├── line:          int|null
│           ├── cwe:           str|null
│           └── evidence:      str|null
│
├── edges: list[Edge]
│   └── Edge
│       ├── id:       str
│       ├── source:   str  (node id)
│       ├── target:   str  (node id)
│       └── animated: bool (true for Confirmed edges)
│
└── stats
    ├── total:             int
    ├── confirmed:         int
    ├── code_only:         int
    ├── runtime_only:      int
    ├── suppression_ratio: float
    └── cwe_types_covered: list[str]  (Objective 01 proof)
```

---

## 7. API Contract

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  METHOD  PATH                         DESCRIPTION                           │
├──────────────────────────────────────────────────────────────────────────────┤
│  GET     /api/graph                   Full correlation graph (≤10s)         │
│  GET     /api/graph?refresh=true      Force re-build (clears cache)         │
│  POST    /api/verify/{id}             Start LangGraph probe (SSE)           │
│  GET     /api/verify/{id}/stream      SSE stream for label updates          │
│  POST    /api/patch/{id}              Generate patch (GPT-4o/template)      │
│  POST    /api/patch/{id}/apply        Apply patch + re-verify               │
│  GET     /api/compliance/{id}         INR risk + 4-framework mapping        │
│  GET     /api/findings                All findings (sorted: Confirmed first) │
│  GET     /api/findings/{id}           Single finding detail                 │
│  GET     /health                      Health check (Docker)                 │
│  GET     /docs                        Swagger UI                            │
└──────────────────────────────────────────────────────────────────────────────┘

SSE Event Format (POST /api/verify/{id}):
  data: {"label": "Code only", "probe_history": [...], "done": false}
  data: {"label": "Confirmed", "evidence": "...", "probe_history": [...], "done": true}

Error Response Format:
  {"detail": "string", "code": "string", "finding_id": "string"}
```

---

## 8. Security Boundaries

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    SECURITY BOUNDARIES                                       │
│                                                                              │
│  1. PROBE CONTAINMENT                                                       │
│     ✅ All probes via internal Docker network only                          │
│     ✅ Target container NOT exposed on host port                            │
│     ✅ 2.0s hard timeout on all probes                                      │
│     ✅ Canary payloads only — no destructive strings                        │
│     ✅ Probes only on SAST-flagged routes — no spider/crawl                 │
│                                                                              │
│  2. SOURCE CODE ACCESS                                                      │
│     ✅ Target source mounted read-only (:ro volume)                         │
│     ✅ AST mapper cannot write to source files                              │
│     ✅ Patch engine writes via git apply — tracked and reversible           │
│                                                                              │
│  3. SECRETS MANAGEMENT                                                      │
│     ✅ Azure OpenAI key in .env only — never in code                       │
│     ✅ .env excluded from git (.gitignore)                                  │
│     ✅ .env.example provided with placeholder values                        │
│     ✅ No secrets in Docker image layers                                    │
│                                                                              │
│  4. LLM SAFETY                                                              │
│     ✅ LLM invoked ONLY after deterministic AST mapping                    │
│     ✅ LLM output validated: must start with "---" or "@@"                 │
│     ✅ Fallback to template if LLM output invalid                           │
│     ✅ temperature=0 for deterministic patch output                         │
│                                                                              │
│  5. DEMO SAFETY                                                             │
│     ✅ Pre-seeded data files — demo works offline                           │
│     ✅ Template patches — demo works without Azure key                     │
│     ✅ No login screen — direct to workbench                                │
│     ✅ No destructive operations in any code path                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Performance Budget

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    PERFORMANCE BUDGET                                        │
│                                                                              │
│  Operation                          Budget    Implementation                │
│  ─────────────────────────────────────────────────────────────────────────  │
│  docker compose up --build          < 60s     cached layers after first run │
│  Target healthcheck pass            < 30s     curl retry 3x with 10s gap   │
│                                                                              │
│  GET /api/graph (cold)              ≤ 10s     AST parse + ELK layout       │
│  GET /api/graph (warm, cached)      < 1s      in-memory cache              │
│                                                                              │
│  Single LangGraph probe             ≤ 2s      httpx timeout=2.0s           │
│  LangGraph probe + retry            ≤ 4s      2 × 2s probes               │
│                                                                              │
│  UI initial render                  ≤ 3s      pre-computed ELK positions   │
│  Node click → detail panel          < 100ms   local state, no API call     │
│  Label badge flip (SSE)             < 500ms   SSE event → React state      │
│                                                                              │
│  Patch generation (GPT-4o)          ≤ 10s     10s timeout on LLM call     │
│  Patch generation (template)        < 50ms    dict lookup                  │
│  git apply --check + apply          < 1s      local file operation         │
│  Re-verification after patch        ≤ 2s      same LangGraph probe        │
│  Total patch + re-verify            ≤ 15s     within budget               │
│                                                                              │
│  Compliance report generation       < 200ms   dict lookup + arithmetic     │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Dependency Graph

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    MODULE DEPENDENCY GRAPH                                   │
│                                                                              │
│  engine/api/main.py                                                         │
│  ├── engine/ingestion/semgrep_parser.py                                     │
│  │   └── engine/ingestion/schema.py  (UnifiedFinding)                      │
│  ├── engine/ingestion/zap_parser.py                                         │
│  │   └── engine/ingestion/schema.py                                         │
│  ├── engine/ingestion/correlator.py                                         │
│  │   └── engine/ingestion/schema.py                                         │
│  ├── engine/ast_mapper/call_graph.py                                        │
│  │   ├── engine/ast_mapper/route_extractor.py  (stdlib: ast, os)           │
│  │   └── engine/ast_mapper/sink_detector.py    (stdlib: ast)               │
│  ├── engine/ast_mapper/merger.py                                            │
│  │   └── engine/ingestion/schema.py                                         │
│  ├── engine/langgraph_loop/graph.py                                         │
│  │   ├── engine/langgraph_loop/state.py                                     │
│  │   └── engine/langgraph_loop/nodes.py        (httpx, os)                 │
│  ├── engine/classifier/classifier.py           (stdlib only)               │
│  ├── engine/patch_engine/patcher.py                                         │
│  │   ├── engine/patch_engine/llm_patcher.py    (openai, os)                │
│  │   └── engine/patch_engine/templates.py      (stdlib only)               │
│  └── engine/compliance/mapping.py                                           │
│      └── engine/compliance/risk_calculator.py  (stdlib only)               │
│                                                                              │
│  Python dependencies:                                                       │
│  fastapi, uvicorn, pydantic>=2, httpx, langgraph, openai                   │
│  (stdlib: ast, os, json, uuid, collections, subprocess, tempfile)          │
│                                                                              │
│  frontend/src/App.tsx                                                       │
│  ├── @xyflow/react           (interactive node graph)                       │
│  ├── elkjs                   (auto-layout)                                  │
│  ├── @tanstack/react-query   (data fetching)                               │
│  └── tailwindcss             (styling)                                      │
│                                                                              │
│  No circular dependencies. Ingestion schema is the only shared module.     │
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                    OBJECTIVE-TO-COMPONENT MAPPING                           │
│                                                                              │
│  OBJECTIVE 01 (Scan Code + App — ≥4 CWE types, one format)                 │
│  └── semgrep_parser.py + zap_parser.py + schema.py (UnifiedFinding)        │
│      CWE coverage: CWE-89✅ CWE-79✅ CWE-94 CWE-347 CWE-502 CWE-78        │
│                                                                              │
│  OBJECTIVE 02 (Correlate + Merge — link runtime→code, each vuln once)      │
│  └── call_graph.py (AST BFS) + merger.py + correlator.py                   │
│      Deduplication via merged_from[] + consumed_dast_ids set                │
│      Deterministic: no LLM in this pipeline stage                          │
│                                                                              │
│  OBJECTIVE 03 (Prioritise — Confirmed/Code only/Runtime only, ranked)      │
│  └── classifier.py + correlator.py (sort) + langgraph_loop/graph.py        │
│      Confirmed always rank 1 in API responses, UI, exports                 │
│      Suppression: Code only + reachable=False → suppressed in default view │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

*Architecture version: 1.0 — Mitigata Hackathon Problem 06 (Flagship)*  
*All diagrams use ASCII art for maximum portability (renders in any Markdown viewer, terminal, or IDE)*  
*Reference: [P06-SAST-DAST-Correlation-Engine.md](P06-SAST-DAST-Correlation-Engine.md) · [P06-Build-Plan.md](P06-Build-Plan.md)*
