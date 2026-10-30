# Architecture: Mitigata PS5 — SAST & DAST Correlation Engine

## System Overview

The engine is composed of seven discrete, independently testable components connected in a pipeline. The sandboxed target application runs in a separate Docker container and is never modified except by the patch engine (with explicit user confirmation).

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        CORRELATION ENGINE                                │
│                                                                          │
│  External inputs (read-only):                                            │
│    data/semgrep-results.json  ←── Semgrep SARIF/JSON                    │
│    data/zap-alerts.json       ←── OWASP ZAP alerts JSON                 │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │ 1. Ingestion Pipeline (engine/ingestion/)                        │    │
│  │    Normalise both inputs → UnifiedFinding schema                 │    │
│  │    Output: List[UnifiedFinding] (cwe_id, file, line, route, ...) │    │
│  └──────────────────────────┬──────────────────────────────────────┘    │
│                             │                                            │
│  ┌──────────────────────────▼──────────────────────────────────────┐    │
│  │ 2. AST Route-to-Sink Mapper (engine/ast_mapper/)                 │    │
│  │    Python ast traversal of target-app/src/                       │    │
│  │    Output: CallGraph — route decorator → controller → sink       │    │
│  │    INVARIANT: deterministic, no LLM, runs before any AI call     │    │
│  └──────────────────────────┬──────────────────────────────────────┘    │
│                             │                                            │
│  ┌──────────────────────────▼──────────────────────────────────────┐    │
│  │ 3. LangGraph Verification Loop (engine/langgraph_loop/)          │    │
│  │    Stateful graph: probe_generator → runtime_executor →          │    │
│  │    response_evaluator → tier assignment                          │    │
│  │    INVARIANT: probes only on SAST-flagged routes                 │    │
│  │    INVARIANT: local Docker network only, 2s timeout              │    │
│  │    INVARIANT: read-only canary strings only                      │    │
│  └──────────────────────────┬──────────────────────────────────────┘    │
│                             │                                            │
│  ┌──────────────────────────▼──────────────────────────────────────┐    │
│  │ 4. 4-Tier Classifier (engine/classifier/)                        │    │
│  │    T1 🔴 Confirmed Exploitable — SAST + DAST match + evidence    │    │
│  │    T2 🟠 Reachable Unverified  — route exposed, probe blocked    │    │
│  │    T3 🟡 Unreachable Code      — sink exists, no route reaches it│    │
│  │    T4 🔵 Runtime Config Only   — missing headers, CORS, TLS      │    │
│  └──────────┬──────────────────────────────────┬───────────────────┘    │
│             │                                  │                         │
│  ┌──────────▼──────────────┐  ┌───────────────▼───────────────────┐    │
│  │ 5. Correlation Graph UI │  │ 6. Git Diff Patch Engine           │    │
│  │    (frontend/)          │  │    (engine/patch_engine/)          │    │
│  │    React + React Flow   │  │    LLM → unified diff → apply →    │    │
│  │    Split-screen:        │  │    re-run same LangGraph probe →   │    │
│  │    graph left | code    │  │    "Fix Verified" or "Re-patch"    │    │
│  │    right                │  │    INVARIANT: human confirms patch  │    │
│  │    ≤ 3s render          │  │    before apply                    │    │
│  └─────────────────────────┘  └───────────────────────────────────┘    │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ 7. Compliance Translator (engine/compliance/)                     │   │
│  │    INR financial exposure = records × cost_per_record × prob      │   │
│  │    Maps T1 findings → RBI CSF / SEBI CSCRF / ISO 27001 controls  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  TARGET APP (separate Docker container — docker-compose service: target) │
│  Sandboxed Flask app with seeded vulnerabilities                         │
│  Network: internal Docker bridge — not reachable from outside host       │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Component Boundaries

### 1. Ingestion Pipeline (`engine/ingestion/`)

**Owns:** Parsing and normalisation of external tool outputs.  
**Input:** `data/semgrep-results.json` (SARIF or JSON), `data/zap-alerts.json`  
**Output:** `List[UnifiedFinding]`  
**Does NOT own:** AST analysis, probe logic, classification

**UnifiedFinding schema:**
```python
{
  "id": str,              # unique finding ID
  "source": "sast"|"dast",
  "cwe_id": str,          # e.g. "CWE-89" — shared correlation key
  "file": str,            # SAST: source file path
  "line": int,            # SAST: line number
  "url": str,             # DAST: endpoint URL
  "method": str,          # DAST: HTTP method
  "parameter": str,       # DAST: vulnerable parameter
  "evidence": str,        # DAST: response evidence
  "rule_id": str,         # SAST: Semgrep rule ID
  "severity": str
}
```

---

### 2. AST Route-to-Sink Mapper (`engine/ast_mapper/`)

**Owns:** Deterministic call graph construction from Python source.  
**Input:** `target-app/src/` Python source files  
**Output:** `CallGraph` — nodes (routes, functions, sinks) + edges (calls)  
**Does NOT own:** Probe logic, classification, LLM calls  
**INVARIANT:** Must complete before any LLM is invoked. No AI-assisted guessing.

**Sink patterns detected:**
- Raw SQL: `db.execute(...)`, `cursor.execute(...)` with f-string or `%` formatting
- Command injection: `os.system(...)`, `subprocess.run(...)`, `subprocess.call(...)`
- Eval: `eval(...)`, `exec(...)`
- Template injection: `render_template_string(...)` with user input
- Unsafe deserialization: `pickle.loads(...)`, `yaml.load(...)` without `Loader`

---

### 3. LangGraph Verification Loop (`engine/langgraph_loop/`)

**Owns:** Stateful probe execution and tier pre-classification.  
**Input:** `UnifiedFinding` with reachable route (from AST mapper)  
**Output:** Updated `UnifiedFinding` with `tier`, `probe_payload`, `http_response`, `evidence`  
**Does NOT own:** Final classification persistence, UI updates, patch generation

**Network boundary:** All `httpx` calls target `http://target-app:8080` only. No external URLs.  
**Timeout:** 2 seconds on all HTTP calls.  
**Payload safety:** Canary strings only — no destructive SQL, no OS commands.

---

### 4. 4-Tier Classifier (`engine/classifier/`)

**Owns:** Final tier assignment and suppression logic.  
**Input:** `UnifiedFinding` with LangGraph output + AST reachability  
**Output:** `ClassifiedFinding` with `tier` (T1/T2/T3/T4) and `suppressed` flag  
**Does NOT own:** Probe execution, patch generation, UI rendering

**Classification rules (in order):**
1. If AST mapper finds no route reaching the sink → **T3** (suppress)
2. If LangGraph probe returns exploitation evidence → **T1**
3. If route is exposed but probe is blocked/inconclusive → **T2**
4. If no code flaw, only config issue (headers/CORS/TLS) → **T4**

---

### 5. Correlation Graph UI (`frontend/`)

**Owns:** Visual rendering of the correlation graph and split-screen detail panel.  
**Input:** REST API from engine backend (FastAPI)  
**Does NOT own:** Probe execution, patch application, classification logic

**Performance invariant:** Full graph must render within 3 seconds of page load.

---

### 6. Git Diff Patch Engine (`engine/patch_engine/`)

**Owns:** Patch generation, application, and re-verification.  
**Input:** T1 `ClassifiedFinding` + source file  
**Output:** Unified Git diff, patch application result, re-verification tier  
**INVARIANT:** Human must confirm patch preview before `apply` is called.  
**INVARIANT:** Re-verification uses the exact same LangGraph probe as original verification.

---

### 7. Compliance Translator (`engine/compliance/`)

**Owns:** Financial risk quantification and regulatory control mapping.  
**Input:** `ClassifiedFinding` (T1 findings)  
**Output:** `ComplianceReport` with INR exposure, RBI/SEBI/ISO 27001 control IDs

**Financial risk formula:**
```
total_exposure_inr = records_at_risk × cost_per_record_inr × breach_probability
cost_per_record_inr = 3500–7000 (IBM Cost of Data Breach 2024, India benchmark)
breach_probability = f(CVSS score, tier)
```

---

## Docker Compose Services

| Service | Port | Purpose |
| --- | --- | --- |
| `target` | 8080 (internal only) | Sandboxed vulnerable Flask app |
| `engine` | 8000 | FastAPI correlation engine backend |
| `frontend` | 3000 | React correlation graph UI |

**Network:** `target` is on an internal bridge network not exposed to the host. Only `engine` can reach `target:8080`.

---

## Data Flow Invariants

1. `data/semgrep-results.json` and `data/zap-alerts.json` are **read-only inputs** — never modified by the engine.
2. The AST call graph is **always built before** any LangGraph node runs.
3. LangGraph probes **never reach** any URL outside `http://target-app:8080`.
4. Patches are **never applied** without an explicit user confirmation action in the UI.
5. The compliance translator **only processes T1 findings** — T2/T3/T4 do not generate INR risk reports.
