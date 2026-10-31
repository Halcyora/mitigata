# P06 Build Plan — Phase-by-Phase Winning Strategy

> **Goal:** Maximum points — 100 base + Flagship Bonus  
> **PRD:** [P06-PRD.md](P06-PRD.md) — source of truth for all requirements  
> **Reference:** [P06-SAST-DAST-Correlation-Engine.md](P06-SAST-DAST-Correlation-Engine.md)  
> **One-command start:** `docker compose up --build` → open `http://localhost:3000`  
> **Build plan version:** 3.3 — Flask + Express adapters and multi-target scanning
> **Three mandatory objectives:** Scan Code+App · Correlate+Merge · Prioritise

---

## PRD Quick Reference

> Full requirements: [P06-PRD.md](P06-PRD.md)

### Answer Key (what judges measure us against)

The counts below describe the controlled Flask fixture only. Evaluate Juice Shop
against its own pinned-revision ground truth and report those results separately.

| Category | Count | Our Label | How We Hit It |
|---|---|---|---|
| Code + Runtime pairs (linkable) | **20** | Confirmed | CWE + route + scope + parameter → merge → LangGraph probe |
| Code only (e.g. hardcoded secrets) | **10** | Code only | SAST only, no DAST match |
| Runtime only (e.g. missing headers) | **6** | Runtime only | DAST only, no SAST match |
| Safe decoys (false positive traps) | **~8** | Should NOT be reported | AST reachability + parameterised query detection |
| **Total planted** | **36** | | |

### Performance Targets We Must Hit

| Metric | Good | Great | Our Strategy |
|---|---|---|---|
| Code detection | > 60% | > 85% | Profile-specific Semgrep packs for Python/Flask and JavaScript |
| Runtime detection | > 50% | > 80% | ZAP scoped to the selected local target profile |
| Correct links | > 50% | > 80% | Target + CWE + normalized route + code scope + attacked parameter; method when known |
| Wrong links | < 20% | < 5% | AST reachability gates correlation |
| False alarms | < 30% | < 10% | Parameterised query detection (B-2) |
| Unseen app | > 40% | > 65% | Shared route contract + framework adapters |
| Run time | < 15 min | < 5 min | Selected target profile + pre-seeded fallback data |

### FR-to-Component Mapping

| FR | Requirement | Component |
|---|---|---|
| FR-1 | SAST scan: file, line, CWE, snippet | `semgrep_parser.py` |
| FR-2 | DAST scan: URL, method, param, payload, evidence | `zap_parser.py` |
| FR-3 | One common format with CWE number | `schema.py` (UnifiedFinding) |
| **FR-4** | **Route map: URL → function → scopes + read parameters** | **`RouteAdapter` + shared schema + Flask/Express adapters** |
| **FR-5** | **Correlate: target + CWE + route + scope + parameter → Confirmed; method/source when known** | **`correlator.py`** |
| **FR-6** | **Merge duplicates: scan twice = same count** | **`correlator.py` (consumed_dast_ids)** |
| FR-7 | Label: Confirmed / Code only / Runtime only | `classifier.py` |
| FR-8 | Issue detail: URL + param + payload + file + line + CWE | `FindingDetailPanel.tsx` |
| FR-9 | Prioritised list: Confirmed first, then risk score | `correlator.py` sort + UI |
| FR-10 | CLI / API / page + README | FastAPI `/api/*` + `README.md` |

### Bonus Features We Implement

| Bonus | Feature | Our Implementation |
|---|---|---|
| **B-1** | Auto-verify Code only → Confirmed | LangGraph verification loop (Phase 4) |
| **B-2** | Cut SAST noise (parameterised queries, dead code) | AST reachability + sink safety check (Phase 3) |
| **B-3** | Explain every link (why joined) | `merged_from[]` + `reason` field in UI |
| **B-4** | Plain-English fix suggestion | Sarvam GLM-5.3 patch + template (Phase 6) |
| B-5 | Compare two scans | Out of scope for v1 |
| **B-6** | Export SARIF + CI fail on confirmed HIGH | SARIF export endpoint `/api/export/sarif` |
| **B-7** | **Second language** | **Express/Node.js adapter + OWASP Juice Shop target profile** |

### Official Vulnerability Types (PRD §5)

| CWE | Type | Mandatory | In Our Sink Detector | In Our Dead Code |
|---|---|---|---|---|
| CWE-89 | SQL Injection | ✅ Yes | ✅ `sql_injection` | ✅ `_legacy_export_users` |
| CWE-79 | XSS | ✅ Yes | ✅ `xss` | ✅ `_legacy_render_xss` |
| CWE-78 | Command Injection | Pick ≥2 | ✅ `command_injection` | ✅ `_legacy_run_report` |
| CWE-22 | Path Traversal | Pick ≥2 | ⚠️ Add to sink detector | ⚠️ Add to dead_code_helpers |
| CWE-601 | Open Redirect | Pick ≥2 | ⚠️ Add to sink detector | ⚠️ Add to dead_code_helpers |
| CWE-798 | Hard-coded Secrets | Pick ≥2 | ✅ `hardcoded_secret` | ✅ (in we45 config) |

> **Action items for CWE-22 and CWE-601:**
> - Add `path_traversal` and `open_redirect` patterns to `sink_detector.py`
> - Add `_legacy_path_read()` and `_legacy_redirect()` functions to `dead_code_helpers.py`
> - Add ZAP sink map entries for cweid 22 and 601

---

## The Three Objectives at a Glance

| Objective | What Judges Score | Key Deliverable |
|---|---|---|
| **01 — Scan Code and App** | ≥4 CWE types, one common format | `UnifiedFinding` schema with `cwe_id` |
| **02 — Correlate and Merge** | Link runtime → code, merge duplicates | Three-pass Flask/Express route adapters + strict merge engine |
| **03 — Prioritise What to Fix** | Confirmed/Code only/Runtime only labels, Confirmed first | Classifier + ranked UI |

---

## Build Order Rationale

Build in **descending scoring weight** so a partial demo still scores maximally:

| Phase | Component | Objectives | Points | Must work before demo |
|---|---|---|---|---|
| 1 | Repo scaffold + Flask and Juice Shop targets | All | — | Yes — everything runs on this |
| 2 | Unified ingestion pipeline | Obj 01 | 30 pts (shared) | Yes |
| 3 ⭐ | Three-pass AST route mapper + strict correlation | Obj 02 | 30 pts (shared) | Yes — highest weight |
| 4 | LangGraph verification loop | Obj 02+03 | 25 pts | Yes |
| 5 | 3-label classifier + prioritised ranking | Obj 03 | 20 pts (shared) | Yes |
| 6 | Git diff auto-remediation | Obj 03 | 20 pts (shared) | Yes |
| 7 | Correlation graph UI | All | 10 pts | Yes |
| 8 | Compliance translator | — | 15 pts | Yes |
| 9 | Demo polish + containerisation verification | — | 10 pts | Yes |

---

## Phase 1 — Repo Scaffold, Target App & Containerisation

**Scoring impact:** Prerequisite for everything. All points depend on this. Containerisation is a hard requirement for Problem 06.

### 1.1 Target apps: Flask baseline + OWASP Juice Shop

Support two selectable targets through application profiles:

- **Flask baseline:** [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App), used for Python AST coverage and the controlled dead-code demo.
- **Express/Node.js target:** [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), used to exercise the JavaScript adapter and a second real application.

The common ingestion, route schema, correlator, classifier, API, and UI remain
language-independent. Route and source-scope discovery are selected by each
profile's language adapter. Flask remains the first implementation and reference
fixture; Juice Shop and Express are an in-scope second target, not a replacement.

| Profile | App | Language/framework | Route adapter | Role |
|---|---|---|---|---|
| `flask_demo` | we45/Vulnerable-Flask-App | Python / Flask | Python `ast` adapter | Baseline, controlled fixtures, fast offline demo |
| `juice_shop` | OWASP Juice Shop | JavaScript / Express | Node.js AST adapter | Second-language validation against a real app |

Keep both target containers isolated on the internal Docker network. Select
which profile to scan or verify explicitly; do not silently combine results
from different target versions or runtimes into a single scan.

### 1.2 Flask reference vulnerability map (from `app/app.py`)

This table and the 36-finding answer-key counts are the Flask reference fixture,
not an aggregate claim about Juice Shop. Keep target coverage reports and
ground-truth evaluation separate by `target_id`. Add a Juice Shop ground-truth
manifest after pinning its source revision; do not copy Flask routes or CWE
counts into that manifest.

| Route | Handler | Vulnerability | CWE | Obj 01 Type | Expected Label |
|---|---|---|---|---|---|
| `POST /login` | `login()` | JWT signed with hardcoded `'secret'` | CWE-347 | Broken Auth | Confirmed 🔴 |
| `POST /register/user` | `reg_customer()` | MD5 password hashing | CWE-916 | Weak Crypto | Confirmed 🔴 |
| `POST /fetch/customer` | `fetch_customer()` | JWT decoded with `verify=False` | CWE-347 | Broken Auth | Confirmed 🔴 |
| `GET /` | `sitemap()` | Exposes full route map | CWE-200 | Info Disclosure | Code only 🟡 |
| `404 handler` | `pnf(e)` | SSTI via `request.url` in `render_template_string` | CWE-94 | SSTI | Code only → Confirmed after probe |
| `_legacy_*` functions | (dead code) | SQLi, CMDi, pickle, eval, SSTI | CWE-89/78/502/95/94 | Multiple | Code only 🟡 (suppressed) |
| Config | `SECRET_KEY_HMAC` | Hardcoded JWT secret | CWE-798 | Hardcoded Creds | Runtime only 🟠 |

**⚠️ Critical port:** The app runs on **port 5050** (`APP_PORT = os.environ.get('APP_PORT', 5050)` in `app/app.py`).

**Key demo moment — SSTI in 404 handler:** The `pnf(e)` function uses `render_template_string(template % request.url)` — SSTI via URL. Reachable by hitting any non-existent route. Perfect live demo: starts as "Code only", LangGraph fires `{{7*7}}` in URL, gets `49` back → flips to "Confirmed" live.

### 1.3 Supplement we45 with dead-code module for guaranteed ≥70% suppression

```python
# targets/vulnerable_flask/dead_code_helpers.py  ← add to fixture, not upstream app.py
"""
Legacy helper functions — not imported or called by any route.
These simulate real-world dead code that SAST flags but DAST cannot reach.
The AST call graph finds NO route leading to any function here → all "Code only" (suppressed).
Covers Objective 01: adds CWE-89, CWE-78, CWE-502, CWE-95, CWE-94, CWE-79 to scan corpus.
"""
import os
import pickle
import sqlite3


def _legacy_export_users(db_path: str, filter_str: str):
    """DEPRECATED. CWE-89 — raw SQL with string concat. No route calls this → Code only."""
    conn = sqlite3.connect(db_path)
    result = conn.execute(
        "SELECT * FROM users WHERE name='" + filter_str + "'"
    ).fetchall()
    return result


def _legacy_run_report(cmd: str):
    """DEPRECATED. CWE-78 — command injection. No route calls this → Code only."""
    return os.popen("generate_report.sh " + cmd).read()


def _legacy_deserialise_session(data: bytes):
    """DEPRECATED. CWE-502 — unsafe pickle. No route calls this → Code only."""
    return pickle.loads(data)


def _legacy_eval_formula(expr: str):
    """DEPRECATED. CWE-95 — eval injection. No route calls this → Code only."""
    return eval(expr)


def _legacy_template_render(user_input: str):
    """DEPRECATED. CWE-94 — SSTI. No route calls this → Code only."""
    from flask import render_template_string
    return render_template_string(user_input)


def _legacy_sql_report(conn, username: str):
    """DEPRECATED. CWE-89 — f-string SQL. No route calls this → Code only."""
    return conn.execute(f"SELECT * FROM orders WHERE user='{username}'").fetchall()


def _legacy_render_xss(user_input: str):
    """DEPRECATED. CWE-79 — XSS via unescaped output. No route calls this → Code only."""
    return f"<div>{user_input}</div>"
```

**Suppression math (Flask fixture only):** 7 findings in `dead_code_helpers.py`
(unreachable) + ~4 reachable findings in `app.py` = ~11 total → ~64%. Add one
more dead function to clear 70%. Report Juice Shop reachability and suppression
independently; never pool denominators across targets.

**Objective 01 coverage from dead_code_helpers.py:** CWE-89 (SQLi) ✅, CWE-79 (XSS) ✅, CWE-78 (CMDi), CWE-94 (SSTI), CWE-502 (Deserialisation), CWE-95 (eval) — 6/6 types covered, well above the 4 minimum.

### 1.4 Monorepo structure

```
mitigata-p06/
├── configs/
│   ├── flask_demo.yaml           ← Python source, target URL, Semgrep packs, excludes
│   └── juice_shop.yaml           ← JavaScript source, target URL, Semgrep packs, excludes
├── targets/
│   ├── vulnerable_flask/         ← we45 Flask target + controlled demo helpers
│   └── juice-shop/               ← OWASP Juice Shop source checkout (not modified)
├── data/
│   ├── ground_truth/
│   │   ├── flask_demo.yaml       ← controlled fixture ground truth
│   │   └── juice_shop.yaml       ← findings verified for pinned Juice Shop revision
│   ├── raw/                       ← per-scan raw tool output
│   └── sample/
│       ├── flask_semgrep.json
│       ├── flask_zap.json
│       ├── juice_semgrep.json
│       └── juice_zap.json        ← per-target offline fixtures
├── engine/
│   ├── adapters/
│   │   ├── base.py               ← RouteAdapter interface and language selection
│   │   ├── flask_adapter.py      ← Python AST: routes, scopes, request reads
│   │   ├── express_adapter.py    ← invokes JS extractor and maps shared schema
│   │   └── js/
│   │       ├── extract_routes.js ← Node AST extraction for Express
│   │       ├── package.json      ← pinned TypeScript Compiler API dependency
│   │       └── package-lock.json
│   ├── api/
│   │   └── main.py                ← FastAPI: /api/graph, /api/verify, /api/patch, /api/compliance
│   ├── ingestion/
│   │   ├── schema.py              ← Pydantic v2 UnifiedFinding (Obj 01 common format)
│   │   ├── semgrep_parser.py      ← Semgrep JSON → UnifiedFinding[]
│   │   ├── zap_parser.py          ← ZAP JSON → UnifiedFinding[]
│   │   └── correlator.py          ← CWE+route+scope+parameter gate → merged findings
│   ├── ast_mapper/
│   │   ├── route_schema.py        ← Shared RouteNode, CodeScope, ParameterRead
│   │   ├── route_extractor.py     ← Adapter dispatch and normalized route index
│   │   ├── sink_detector.py       ← Shared sink contract and result schema
│   │   ├── python_sink_visitor.py ← Python AST sink patterns
│   │   ├── javascript_sink_visitor.py ← Express/JavaScript sink patterns
│   │   ├── call_graph.py          ← Adapter-provided one-hop scopes + request reads
│   │   └── merger.py              ← Enrich SAST findings with AST reachability
│   ├── langgraph_loop/
│   │   ├── state.py               ← AlertState TypedDict
│   │   ├── nodes.py               ← probe_generator, runtime_executor, response_evaluator
│   │   └── graph.py               ← StateGraph with conditional retry edge
│   ├── classifier/
│   │   └── classifier.py          ← Confirmed/Code only/Runtime only + ranking (Obj 03)
│   ├── patch_engine/
│   │   ├── templates.py           ← Deterministic patches (zero cost, demo-safe)
│   │   ├── llm_patcher.py         ← Sarvam Token Factory GLM-5.3
│   │   └── patcher.py             ← LLM → template fallback orchestrator
│   └── compliance/
│       ├── risk_calculator.py     ← INR exposure (IBM 2024 India benchmark)
│       └── mapping.py             ← RBI + SEBI + ISO 27001 + DPDP 2023
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── CorrelationGraph.tsx     ← React Flow attack path graph
│   │   │   ├── FindingDetailPanel.tsx   ← Split-screen detail (code + HTTP trace)
│   │   │   ├── BusinessRiskPanel.tsx    ← INR + compliance frameworks
│   │   │   └── ReTestButton.tsx         ← Live re-verify button
│   │   └── App.tsx
│   └── package.json
├── tests/
│   ├── test_ingestion.py
│   ├── test_flask_adapter.py
│   ├── test_express_adapter.py
│   ├── test_route_schema.py
│   ├── test_ast_mapper.py
│   ├── test_correlator.py
│   ├── test_classifier.py
│   └── test_compliance.py
├── scripts/
│   ├── run_scan.py               ← run_scan.py configs/{profile}.yaml
│   ├── load_sample.py            ← offline sample loader
│   └── evaluate.py               ← compare results with target ground truth
├── docker-compose.yml            ← one-command startup
├── .env.example
├── AGENTS.md
├── ARCHITECTURE.md
├── BUILD.md
└── README.md
```

### 1.5 Docker Compose (Flask + Juice Shop, isolated targets)

```yaml
# docker-compose.yml
version: "3.9"

services:
  target-flask:
    build: ./targets/vulnerable_flask
    container_name: mitigata-target-flask
    ports:
      - "127.0.0.1:5050:5050"
    networks:
      - internal
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5050/"]
      interval: 10s
      timeout: 5s
      retries: 3
    # Host access is restricted to localhost.

  target-juice-shop:
    build: ./targets/juice-shop
    container_name: mitigata-target-juice-shop
    ports:
      - "127.0.0.1:3001:3000"
    networks:
      - internal
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://localhost:3000').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]
      interval: 10s
      timeout: 5s
      retries: 6
    # Build Juice Shop from the checked-out source used by the Express adapter.
    # Host port 3001 avoids conflicting with the frontend on port 3000.
    # Bind to localhost only; do not expose this intentionally vulnerable app to the LAN.

  engine:
    build: ./engine
    container_name: mitigata-engine
    ports:
      - "8000:8000"                 # FastAPI + Swagger docs accessible from host
    networks:
      - internal                    # can reach target
      - public                      # accessible from frontend + host
    environment:
      - TARGETS_ROOT=/targets
      - TARGET_PROFILE=${TARGET_PROFILE:-flask_demo}
    volumes:
      - ./targets:/targets:ro        # source for both adapters, read-only
      - ./configs:/app/configs:ro
      - ./data:/app/data             # raw and per-profile sample scan results
    env_file: .env
    depends_on:
      target-flask:
        condition: service_healthy
      target-juice-shop:
        condition: service_healthy   # wait for target before starting probes

  frontend:
    build: ./frontend
    container_name: mitigata-frontend
    ports:
      - "3000:3000"                 # React UI accessible from host
    networks:
      - public
    depends_on:
      - engine

networks:
  internal:
    internal: true   # both target containers unreachable from host machine
  public:            # engine API + frontend accessible from host
```

### 1.6 .env.example

```bash
# .env.example — copy to .env and fill in values

# Select one profile per scan; supported: flask_demo, juice_shop
TARGET_PROFILE=flask_demo
TARGETS_ROOT=/targets

# Sarvam Token Factory — OpenAI-compatible API
SARVAM_API_KEY=your-sarvam-api-key
SARVAM_BASE_URL=https://api.sarvam.ai/v2
SARVAM_MODEL=glm5.3

# Leave blank to use template patches only (zero cost, demo-safe)
# SARVAM_API_KEY=
```

Profile contracts (`configs/flask_demo.yaml` and
`configs/juice_shop.yaml`):

```yaml
target_id: flask_demo
language: python
framework: flask
source_dir: /targets/vulnerable_flask/source
target_url: http://target-flask:5050
semgrep_configs:
  - p/python
  - p/flask
  - p/security-audit
exclude:
  - .venv
adapter: flask
```

```yaml
target_id: juice_shop
language: javascript
framework: express
source_dir: /targets/juice-shop/source
target_url: http://target-juice-shop:3000
semgrep_configs:
  - p/javascript
  - p/security-audit
exclude:
  - node_modules
adapter: express
```

Treat these as per-scan inputs; the API, stored results, and scanner output
retain `target_id` so findings from different applications never correlate.

### 1.7 Target container build inputs

```dockerfile
# targets/vulnerable_flask/Dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV APP_PORT=5050
EXPOSE 5050
CMD ["python", "app/app.py"]
```

Build Juice Shop from its checked-out repository and retain a lockfile/commit
identifier for each profile. The Express adapter reads that exact checkout
mounted read-only into the engine; scanner and route results must refer to the
same target revision.

### 1.8 Profile-based scanning and pre-seeded data

```bash
# Select a target; configs contain source_dir, target_url, language,
# Semgrep packs, excludes, and target revision.
python scripts/run_scan.py configs/flask_demo.yaml
python scripts/run_scan.py configs/juice_shop.yaml

# Flask profile Semgrep equivalent
semgrep --config=p/python \
        --config=p/security-audit \
        --config=p/flask \
        --json targets/vulnerable_flask/ > data/raw/flask-semgrep.json

# Juice Shop profile Semgrep equivalent
semgrep --config=p/javascript \
        --config=p/security-audit \
        --json targets/juice-shop/ > data/raw/juice-semgrep.json

# Run ZAP against the selected internal target URL from the profile.
# Keep scans scoped to that local target; no host.docker.internal route.
python scripts/run_scan.py configs/flask_demo.yaml --dast
python scripts/run_scan.py configs/juice_shop.yaml --dast

# Load committed per-profile fixtures for offline/demo runs.
python scripts/load_sample.py configs/flask_demo.yaml
python scripts/load_sample.py configs/juice_shop.yaml
```

---

## Phase 2 — Unified Ingestion Pipeline (Objective 01)

**Scoring impact:** Foundation of Objective 01 — one common format with CWE numbers.

### 2.1 UnifiedFinding schema (Pydantic v2) — the common format for Obj 01

```python
# engine/ingestion/schema.py
from pydantic import BaseModel, Field
from typing import Optional, Literal
import uuid


class UnifiedFinding(BaseModel):
    """
    The single common format required by Objective 01.
    Both SAST and DAST findings normalise into this schema.
    cwe_id is the shared key for Objective 02 correlation.
    label is the Objective 03 prioritisation output.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str                         # profile identity; prevents cross-target joins
    source: Literal["sast", "dast"]
    cwe_id: str                              # MANDATORY — Obj 01 CWE number requirement
    label: Optional[Literal[
        "Confirmed",                         # Obj 03 Rank 1 — both SAST + DAST
        "Code only",                         # Obj 03 Rank 2 — SAST only
        "Runtime only",                      # Obj 03 Rank 3 — DAST only
    ]] = None

    # Code location (from SAST + AST mapper)
    file: Optional[str] = None
    line: Optional[int] = None
    function: Optional[str] = None
    sink_type: Optional[str] = None         # e.g. "sql_injection", "ssti"

    # Runtime proof (from DAST + LangGraph)
    url: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None
    parameter_source: Optional[Literal["path", "query", "form", "json", "header"]] = None
    evidence: Optional[str] = None
    http_status: Optional[int] = None

    # Correlation metadata
    rule_id: Optional[str] = None
    severity: str = "MEDIUM"
    reachable: Optional[bool] = None        # set by AST mapper
    routes: list[str] = Field(default_factory=list)
    merged_from: list[str] = Field(default_factory=list)   # Obj 02 dedup tracking
    confidence: Optional[float] = None      # 0.0–1.0

    model_config = {"json_schema_extra": {"example": {
        "id": "abc-123",
        "target_id": "flask_demo",
        "source": "sast",
        "cwe_id": "CWE-89",
        "label": "Confirmed",
        "file": "app/app.py",
        "line": 47,
        "severity": "HIGH",
        "sink_type": "sql_injection",
    }}}
```

### 2.2 Semgrep JSON parser (Objective 01 — CWE extraction)

```python
# engine/ingestion/semgrep_parser.py
import json
from .schema import UnifiedFinding

# CWE map: use metadata first; rule fallback covers both Python and JavaScript rules
CWE_MAP = {
    "python.lang.security.audit.dangerous-system-call":                "CWE-78",
    "python.lang.security.audit.eval-detected":                        "CWE-95",
    "python.lang.security.deserialization.avoid-pickle":               "CWE-502",
    "python.lang.security.audit.hardcoded-password":                   "CWE-798",
    "python.lang.security.audit.hardcoded-secret":                     "CWE-798",
    "python.flask.security.injection.tainted-string-from-http-params": "CWE-89",
    "python.flask.security.xss.audit.template-unescaped-extension":    "CWE-79",
    "python.flask.security.audit.render-template-string":              "CWE-94",
    "python.jwt.security.unverified-jwt-decode":                       "CWE-347",
    "python.jwt.security.jwt-hardcoded-secret":                        "CWE-347",
    "python.sqlalchemy.security.sqlalchemy-execute-injection":         "CWE-89",
    "python.lang.security.audit.formatted-sql-query":                  "CWE-89",
    "python.lang.security.audit.use-of-md5":                          "CWE-916",
}

SINK_TYPE_MAP = {
    "CWE-89":  "sql_injection",
    "CWE-78":  "command_injection",
    "CWE-94":  "ssti",
    "CWE-95":  "eval_injection",
    "CWE-347": "jwt_weak_secret",
    "CWE-502": "insecure_deserialisation",
    "CWE-798": "hardcoded_secret",
    "CWE-916": "weak_hash",
    "CWE-79":  "xss",
    "CWE-200": "information_disclosure",
}


def parse_semgrep_json(path: str, target_id: str) -> list[UnifiedFinding]:
    with open(path) as f:
        data = json.load(f)
    findings = []
    for result in data.get("results", []):
        rule_id = result["check_id"]
        metadata = result.get("extra", {}).get("metadata", {})
        cwe_raw = metadata.get("cwe", [])
        if isinstance(cwe_raw, list) and cwe_raw:
            cwe = cwe_raw[0].split(":")[0].strip()
        elif isinstance(cwe_raw, str):
            cwe = cwe_raw.split(":")[0].strip()
        else:
            cwe = CWE_MAP.get(rule_id, "CWE-UNKNOWN")

        findings.append(UnifiedFinding(
            target_id=target_id,
            source="sast",
            cwe_id=cwe,
            file=normalize_finding_path(result["path"], target_id),
            line=result["start"]["line"],
            rule_id=rule_id,
            severity=result.get("extra", {}).get("severity", "WARNING").upper(),
            sink_type=SINK_TYPE_MAP.get(cwe, "unknown"),
            label="Code only",   # default — overridden by correlator/classifier
        ))
    return findings
```

### 2.3 ZAP JSON parser

```python
# engine/ingestion/zap_parser.py
import json
from .schema import UnifiedFinding

ZAP_SINK_MAP = {
    "89":  "sql_injection",
    "78":  "command_injection",
    "79":  "xss",
    "94":  "ssti",
    "502": "insecure_deserialisation",
    "200": "information_disclosure",
    "347": "jwt_weak_secret",
}

ZAP_PARAM_SOURCE_MAP = {
    "URL_PATH": "path",
    "GET": "query",
    "POST_DATA": "form",
    "JSON": "json",
    "HEADER": "header",
}

_RISK_NORMALISE = {
    "High (Medium)": "HIGH", "High (High)": "HIGH",
    "Medium (Medium)": "MEDIUM", "Low (Low)": "LOW",
    "Informational": "INFO",
}


def parse_zap_json(path: str, target_id: str) -> list[UnifiedFinding]:
    with open(path) as f:
        data = json.load(f)

    alerts = data.get("alerts", [])
    if not alerts:
        for site in data.get("site", []):
            alerts.extend(site.get("alerts", []))

    findings = []
    for alert in alerts:
        cweid = str(alert.get("cweid", "0"))
        risk = alert.get("riskdesc", "Medium")
        findings.append(UnifiedFinding(
            target_id=target_id,
            source="dast",
            cwe_id=f"CWE-{cweid}",
            url=alert.get("url"),
            method=alert.get("method"),
            parameter=alert.get("param"),
            parameter_source=ZAP_PARAM_SOURCE_MAP.get(alert.get("paramType")),
            evidence=alert.get("evidence", "")[:500],
            severity=_RISK_NORMALISE.get(risk, risk.split(" ")[0].upper()),
            sink_type=ZAP_SINK_MAP.get(cweid, "unknown"),
            label="Runtime only",   # default — overridden by correlator
        ))
    return findings
```

`normalize_finding_path` removes the profile's source-root prefix and stores a
stable target-relative path. Both adapters and Semgrep results must use the same
relative-path convention so scope checks work across Windows/Linux containers.
The Semgrep parser prefers CWE metadata for either language and uses a
language-specific `check_id` fallback only when metadata is missing.

### 2.4 Correlation and Merge Engine (Objective 02 — the core)

The correlation gate is deliberately stricter than a CWE-only or substring URL join.
Pass 1 supplies normalized route templates, Pass 2 supplies route code scopes, and
Pass 3 supplies the input parameter names read by each handler. A SAST/DAST pair is
`Confirmed` only when CWE, normalized route, code scope, and attacked parameter
all match; HTTP method must also match when the DAST method is known. When
available, the parameter source (query/body/path/header) must match as well.
A CWE match without these links is not sufficient evidence to merge.

```python
# engine/ingestion/correlator.py
from urllib.parse import urlparse
from .schema import UnifiedFinding
from ..ast_mapper.route_schema import RouteNode


def correlate_and_merge(
    sast: list[UnifiedFinding],
    dast: list[UnifiedFinding],
    routes: list[RouteNode],
) -> list[UnifiedFinding]:
    """
    Confirm a pair only when target, CWE, normalized route, code scope, and
    input parameter all match. A known HTTP method/source must also match.
    """
    merged: list[UnifiedFinding] = []
    consumed_dast_ids: set[str] = set()

    for s in sast:
        candidates = []
        for d in dast:
            if d.id in consumed_dast_ids:
                continue
            if d.target_id != s.target_id:
                continue
            if d.cwe_id != s.cwe_id or not d.url:
                continue
            path = urlparse(d.url).path
            candidates.extend(
                (route, d) for route in routes
                if route.target_id == s.target_id
                and route.matches_path(path)
                and route.matches_method(d.method)
                and route.contains_location(s.file, s.line)
                and any(
                    read.name == d.parameter
                    and (
                        d.parameter_source is None
                        or read.source == d.parameter_source
                    )
                    for read in route.input_parameters
                )
            )

        if candidates:
            route, best_dast = candidates[0]
            consumed_dast_ids.add(best_dast.id)
            merged.append(s.model_copy(update={
                "label": "Confirmed",
                "url": best_dast.url,
                "method": best_dast.method,
                "parameter": best_dast.parameter,
                "parameter_source": best_dast.parameter_source,
                "evidence": best_dast.evidence,
                "http_status": best_dast.http_status,
                "merged_from": [s.id, best_dast.id],
                "confidence": 0.95,
                "routes": [route.normalized_url],
            }))
        else:
            merged.append(s.model_copy(update={
                "label": "Code only",
                "reachable": any(
                    route.target_id == s.target_id
                    and route.contains_location(s.file, s.line)
                    for route in routes
                ),
            }))

    for d in dast:
        if d.id not in consumed_dast_ids:
            merged.append(d.model_copy(update={"label": "Runtime only"}))

    label_rank = {"Confirmed": 0, "Code only": 1, "Runtime only": 2}
    merged.sort(key=lambda f: label_rank.get(f.label or "Code only", 1))
    return merged
```

`RouteNode.matches_method(None)` treats an absent DAST method as unknown;
otherwise it requires the method to match. `parameter_source` is compared when
the scanner supplies it; the parameter name must always match.

---

## Phase 3 — Three-Pass AST Route Mapper ⭐ (Objective 02 — Highest Weight)

**Scoring impact:** The core of the 30-pt criterion. This is what judges scrutinise most.

The mapper builds one unified `RouteNode` per HTTP endpoint, then enriches it in
three deterministic passes. It replaces line-range-only matching as the source of
route evidence; line ranges remain useful as code-scope metadata, not as the route
join by themselves.

| Pass | Name | Responsibility | Output |
|---|---|---|---|
| 1 | Route and prefix mapping (SpecWeaver-lite) | Flask decorators/Blueprint registrations or Express route declarations/`app.use()` mounts; normalize dynamic segments | `target_id`, `normalized_url`, method, handler |
| 2 | One-hop callee mapping (CPG-lite) | Resolve directly called local/imported project helpers using language-specific symbol resolution | Handler and direct-callee scopes |
| 3 | Input parameter extraction (Respector-lite) | Find framework request reads in the handler and one-hop callees | `input_parameters` with source kinds |

Both adapters implement the same contract and return shared route records; the
correlator does not parse Python or JavaScript. Python uses the built-in `ast`
module. Express uses a small Node.js extractor based on the TypeScript Compiler
API (or Babel parser if required by the selected Juice Shop source syntax), with
JSON output consumed by the Python engine. Pin the Node version and parser
dependency in the extractor package/lockfile.

#### Unified route node

Add `engine/ast_mapper/route_schema.py`. Each route stores its target profile,
original and normalized path, HTTP methods, handler identity, code scopes, and
parameter reads. `CodeScope` carries a target-relative `file`, `start_line`,
`end_line`, and `function`; `ParameterRead` carries `name` and `source` (`path`,
`query`, `form`, `json`, or `header`). The schema must not expose absolute host
paths in API output.

Example after all three passes:

```text
RouteNode(
    target_id="juice_shop",
    normalized_url="/api/orders/{param}",
    methods=["GET"],
    handler="orders.listOrders",
    scopes=[orders.js:10-25, db.js:45-60],
    input_parameters=[
        ParameterRead(name="id", source="path"),
        ParameterRead(name="q", source="query"),
    ],
)
```

The example preserves parameter names for correlation while using a consistent
`{param}` placeholder for URL matching. Typed Flask converters such as
`<int:id>` and Express `:id` map to the same placeholder; the declared name and
location are retained separately in the route metadata.

#### Adapter contract

```python
class RouteAdapter(Protocol):
    def discover_routes(self, profile: TargetProfile) -> list[RouteNode]: ...
```

`flask_adapter.py` parses Flask route decorators and Blueprint mount calls.
`express_adapter.py` invokes `js/extract_routes.js`, validates its JSON, and
converts output into the shared schema. The JS extractor parses Express
`app.get/post/...`, `router.get/post/...`, `router.route(...).get/post(...)`,
and `app.use(prefix, router)` mounts. Static literal prefixes are joined in
declaration order; dynamic/unresolved mounts are explicitly marked and cannot
produce a strict route match.

### 3.1 Pass 1 — Route declarations, prefixes, and URL normalization

Each adapter must join the framework mount prefix to its route before
normalization. A Flask Blueprint mounted at `/api` with
`@bp.route("/orders/<int:id>")` and an Express router mounted with
`app.use("/api", ordersRouter)` where it declares `ordersRouter.get("/orders/:id", ...)`
both resolve to `/api/orders/{param}`. Normalize trailing slashes consistently
and preserve the original path for diagnostics. Multiple static mounts yield one
route per effective path. A dynamic/unresolved prefix remains unresolved; never
silently invent a path.

```python
# engine/adapters/flask_adapter.py
import ast
import os
from typing import Optional

FLASK_ROUTE_DECORATORS = {
    "app.route", "app.get", "app.post", "app.put", "app.delete", "app.patch",
    "bp.route", "bp.get", "bp.post",
}


def extract_routes(src_dir: str) -> list[RouteNode]:
    # Pass 1 has two stages:
    # 1. Index route decorators and Blueprint declarations by module/symbol.
    # 2. Resolve app.register_blueprint(bp, url_prefix=...) mounts, join the
    #    mount prefix to each route path, then normalize dynamic segments.
    # Keep unresolved/dynamic registrations explicitly marked for diagnostics.
    ...


def normalize_route_path(path: str) -> str:
    """Convert Flask <converter:name> segments to the shared {param} form."""
    ...


def resolve_blueprint_prefixes(src_dir: str) -> dict[str, list[str]]:
    """Resolve all statically declared Flask Blueprint mount prefixes."""
    ...
```

### 3.2 Sink detector (shared findings, language-specific AST visitors)

`sink_detector.py` defines the common sink record and CWE/sink-type mapping.
`python_sink_visitor.py` uses Python `ast`; `javascript_sink_visitor.py` uses
the same TypeScript Compiler API parser as the Express adapter. The JavaScript
visitor must report target-relative source spans in the same `CodeScope` format.
Semgrep remains the primary cross-language source of SAST findings; these
visitors add deterministic route-to-sink evidence and do not replace Semgrep.

```python
# engine/ast_mapper/sink_detector.py
import ast

# Sink patterns covering Objective 01 mandatory CWE types (CWE-89, CWE-79 + 4 more)
SINK_PATTERNS: dict[str, callable] = {
    "sql_injection":          lambda n: (           # CWE-89 MANDATORY (Obj 01)
        isinstance(n, ast.Call) and
        isinstance(n.func, ast.Attribute) and
        n.func.attr == "execute" and
        _has_tainted_arg(n.args)
    ),
    "xss":                    lambda n: (           # CWE-79 MANDATORY (Obj 01)
        isinstance(n, ast.Call) and
        isinstance(n.func, ast.Name) and
        n.func.id in ("render_template_string", "Markup") and
        len(n.args) > 0
    ),
    "command_injection":      lambda n: (           # CWE-78
        isinstance(n, ast.Call) and
        isinstance(n.func, ast.Attribute) and
        n.func.attr in ("system", "popen", "run", "call", "check_output") and
        _has_tainted_arg(n.args)
    ),
    "eval_injection":         lambda n: (           # CWE-95
        isinstance(n, ast.Call) and
        isinstance(n.func, ast.Name) and
        n.func.id in ("eval", "exec")
    ),
    "insecure_deserialisation": lambda n: (         # CWE-502
        isinstance(n, ast.Call) and
        isinstance(n.func, ast.Attribute) and
        n.func.attr == "loads" and
        _is_pickle_loads(n)
    ),
    "ssti":                   lambda n: (           # CWE-94
        isinstance(n, ast.Call) and
        isinstance(n.func, ast.Name) and
        n.func.id == "render_template_string"
    ),
    "jwt_weak_secret":        lambda n: (           # CWE-347
        isinstance(n, ast.Call) and
        isinstance(n.func, ast.Attribute) and
        n.func.attr == "decode" and
        _has_verify_false(n.keywords)
    ),
    "weak_hash":              lambda n: (           # CWE-916
        isinstance(n, ast.Call) and
        isinstance(n.func, ast.Attribute) and
        n.func.attr == "md5"
    ),
}


def _has_tainted_arg(args: list) -> bool:
    return any(isinstance(a, (ast.BinOp, ast.JoinedStr, ast.Call, ast.Name)) for a in args)


def _is_pickle_loads(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            return node.func.value.id == "pickle"
    return True


def _has_verify_false(keywords: list) -> bool:
    return any(
        kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False
        for kw in keywords
    )


def find_sinks_in_function(func_node: ast.FunctionDef, file: str) -> list[dict]:
    sinks = []
    for node in ast.walk(func_node):
        for sink_type, matcher in SINK_PATTERNS.items():
            try:
                if matcher(node):
                    sinks.append({
                        "file": file,
                        "line": getattr(node, "lineno", 0),
                        "sink_type": sink_type,
                        "function": func_node.name,
                        "col": getattr(node, "col_offset", 0),
                    })
            except Exception:
                continue
    return sinks
```

### 3.3 Pass 2 — Direct callee scopes (CPG-lite)

Each language adapter indexes local functions and imports, resolves direct calls
from route handlers, and adds exact helper file/line spans to `scopes`. This is
intentionally one hop in v1: do not imply transitive reachability when a helper
calls another helper. Keep unresolved external/library calls out of project
scopes. Express import aliases and re-exports that cannot be statically resolved
must remain explicit unresolved references, not guessed helper links.

```python
# engine/ast_mapper/call_graph.py (shared orchestration over adapter output)


def build_call_graph(profile: TargetProfile) -> dict:
    """Dispatch to the profile adapter and return the shared route index."""
    adapter = adapter_for(profile.language, profile.framework)
    routes = adapter.discover_routes(profile)
    adapter.add_one_hop_scopes(routes, profile)
    adapter.extract_request_parameters(routes, profile)
    return {
        "routes": routes,
        "stats": summarize_route_and_sink_coverage(routes, profile),
    }
```

### 3.4 Pass 3 — Request parameter extraction (Respector-lite)

Walk each route handler and its one-hop callee syntax trees for framework request
reads. Flask reads include `request.args["q"]` / `.get("q")`, `request.form`,
`request.json`, headers, and path arguments. Express reads include
`req.query.q`, `req.query["q"]`, `req.params.id`, `req.body.q`, and headers.
Record each as a `ParameterRead(name, source)` where source is `path`, `query`,
`form`, `json`, or `header`. Only statically observed names can satisfy
correlation; dynamic/unknown keys do not act as wildcards.

The adapter contract also includes `add_one_hop_scopes(routes, profile)` and
`extract_request_parameters(routes, profile)`. Each adapter parses source once
where practical and populates identical `CodeScope` and `ParameterRead` model
types.

The correlator receives the final route list as `call_graph["routes"]`;
`input_parameters` is a list of `ParameterRead` values.

**Critical Phase 3 acceptance checks (both adapters):**

- Blueprint `/api` + route `/orders/<int:id>` produces `/api/orders/{param}`.
- Express `app.use("/api", ordersRouter)` + `ordersRouter.get("/orders/:id", ...)` produces `/api/orders/{param}`.
- Flask `request.args.get("q")` and Express `req.query.q` both record `ParameterRead("q", "query")`.
- DAST `/api/orders/42?q=test` matches that template and extracts `q` as the attacked query parameter.
- SAST locations in an imported direct helper's source span are in route scope for both languages; unrelated files/functions are not.
- Same CWE/URL/parameter findings from different `target_id` values never correlate.
- The route records path `id` and query `q` reads independently.
- Correlation requires route + scope + attacked parameter + CWE; wrong parameter, route, or CWE does not produce `Confirmed`.
- Unresolved mounts, imports, missing SAST locations, or dynamic request keys remain explicit/unmatched rather than becoming broad matches.

**Critical suppression target:** For the controlled Flask fixture,
`call_graph["stats"]["suppression_ratio"] >= 0.70`. Report Juice Shop's measured
ratio separately; do not assume the planted Flask dead-code ratio applies to it.

### 3.5 Merger: enrich SAST findings with AST reachability

```python
# engine/ast_mapper/merger.py
from ..ingestion.schema import UnifiedFinding


def enrich_findings_with_ast(
    findings: list[UnifiedFinding],
    call_graph: dict,
) -> list[UnifiedFinding]:
    """Set route evidence when the SAST location is inside a route code scope."""

    enriched = []
    routes = call_graph["routes"]
    for f in findings:
        if f.source != "sast":
            enriched.append(f)
            continue
        matching_routes = [
            route.normalized_url for route in routes
            if route.target_id == f.target_id
            and route.contains_location(f.file, f.line)
        ]
        f = f.model_copy(update={
            "reachable": bool(matching_routes),
            "routes": matching_routes,
        })
        enriched.append(f)
    return enriched
```

---

## Phase 4 — LangGraph Verification Loop (Objective 02 + 03)

**Scoring impact:** 25 pts. Judges watch this live. The label flip from "Code only" → "Confirmed" is the demo moment.

### 4.1 AlertState

```python
# engine/langgraph_loop/state.py
from typing import TypedDict, Literal, Optional


class AlertState(TypedDict):
    finding_id: str
    target_id: str
    route: str
    method: str
    parameter: str
    parameter_source: str
    sink_type: str
    probe_payload: str
    probe_variant: int           # 0 = first attempt, 1 = retry
    http_status: Optional[int]
    http_response: Optional[str]
    evidence: Optional[str]
    label: Literal["Confirmed", "Code only", "Runtime only", "UNVERIFIED"]
    error: Optional[str]
    probe_history: list[dict]    # audit log — shown in UI detail panel
```

### 4.2 Canary payloads (safe read-only strings — never destructive)

```python
# engine/langgraph_loop/nodes.py
import httpx
from .state import AlertState

CANARY_PAYLOADS: dict[str, list[str]] = {
    "sql_injection":          ["' OR '1'='1",          "' OR 1=1--"],
    "xss":                    ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "command_injection":      ["; echo CANARY_MITIGATA_2026", "| echo CANARY_MITIGATA_2026"],
    "ssti":                   ["{{7*7}}",               "${7*7}"],
    "jwt_weak_secret":        [
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJ1c2VyIjoiYWRtaW4ifQ"
        ".dyt0CoTl4WoVjAHI9Q_CwSKhl6d_9rhM3NrXuJttkao",
    ],
    "eval_injection":         ["__import__('os').getcwd()", "1+1"],
    "insecure_deserialisation": ["",                    "\x80\x04\x95"],
    "weak_hash":              ["test",                  "password"],
    "hardcoded_secret":       ["",                      ""],
}

EVIDENCE_SIGNALS: dict[str, list[str]] = {
    "sql_injection":           ["OperationalError", "sqlite3", "syntax error", "OR '1'='1"],
    "xss":                     ["<script>", "alert(1)", "onerror"],
    "command_injection":       ["CANARY_MITIGATA_2026"],
    "ssti":                    ["49", "Jinja2", "TemplateError"],
    "jwt_weak_secret":         ["Authenticated", "True", "admin", "User"],
    "eval_injection":          ["/app", "getcwd", "/target"],
    "insecure_deserialisation": ["pickle", "UnpicklingError"],
    "weak_hash":               ["md5", "hash"],
}


def probe_generator(state: AlertState) -> AlertState:
    payloads = CANARY_PAYLOADS.get(state["sink_type"], ["CANARY_MITIGATA"])
    variant = state.get("probe_variant", 0)
    state["probe_payload"] = payloads[min(variant, len(payloads) - 1)]
    return state


def runtime_executor(state: AlertState) -> AlertState:
    try:
        profile = load_target_profile(state["target_id"])
        url = build_local_probe_url(profile, state)
        params = {state["parameter"]: state["probe_payload"]}
        json_body = params if state["parameter_source"] == "json" else None
        form_body = params if state["parameter_source"] == "form" else None
        headers = (
            {state["parameter"]: state["probe_payload"]}
            if state["parameter_source"] == "header" else None
        )
        r = httpx.request(
            method=state["method"],
            url=url,
            json=json_body,
            data=form_body,
            params=params if state["parameter_source"] == "query" else None,
            headers=headers,
            timeout=2.0,
            follow_redirects=True,
        )
        state["http_status"] = r.status_code
        state["http_response"] = r.text[:500]
        state["probe_history"] = state.get("probe_history", []) + [{
            "variant": state.get("probe_variant", 0),
            "payload": state["probe_payload"],
            "status": r.status_code,
            "response_preview": r.text[:200],
        }]
    except httpx.TimeoutException:
        state["error"] = "probe_timeout"
        state["label"] = "Code only"
    except Exception as e:
        state["error"] = str(e)[:200]
        state["label"] = "Code only"
    return state


def response_evaluator(state: AlertState) -> AlertState:
    if state.get("error"):
        return state
    response = state.get("http_response", "")
    signals = EVIDENCE_SIGNALS.get(state["sink_type"], [])
    found = [s for s in signals if s in response]
    if found:
        state["evidence"] = f"Response contained exploitation signals: {found}"
        state["label"] = "Confirmed"   # Objective 03: flip to Confirmed
    else:
        state["label"] = "Code only"
    return state


def retry_evaluator(state: AlertState) -> AlertState:
    state["probe_variant"] = state.get("probe_variant", 0) + 1
    state["error"] = None
    state["http_response"] = None
    return state


def should_retry(state: AlertState) -> str:
    if state["label"] == "Code only" and state.get("probe_variant", 0) == 0:
        return "retry"
    return "end"
```

`build_local_probe_url` materializes a concrete path parameter from the selected
profile's route template and sample values, and validates that it stays on that
profile's configured local target. Never probe an arbitrary host taken from a
finding URL. For a known DAST URL, retain its path/query values but rebuild the
origin from the selected profile.

### 4.3 Wire the graph (with conditional retry edge)

```python
# engine/langgraph_loop/graph.py
from langgraph.graph import StateGraph, END
from .state import AlertState
from .nodes import probe_generator, runtime_executor, response_evaluator, retry_evaluator, should_retry


def build_verification_graph():
    g = StateGraph(AlertState)
    g.add_node("probe_generator",    probe_generator)
    g.add_node("runtime_executor",   runtime_executor)
    g.add_node("response_evaluator", response_evaluator)
    g.add_node("retry_evaluator",    retry_evaluator)

    g.set_entry_point("probe_generator")
    g.add_edge("probe_generator",    "runtime_executor")
    g.add_edge("runtime_executor",   "response_evaluator")
    g.add_conditional_edges(
        "response_evaluator",
        should_retry,
        {"retry": "retry_evaluator", "end": END},
    )
    g.add_edge("retry_evaluator", "probe_generator")

    return g.compile()


verification_graph = build_verification_graph()
```

---

## Phase 5 — 3-Label Classifier (Objective 03)

**Scoring impact:** Part of the 20-pt criterion. Confirmed must always rank first.

```python
# engine/classifier/classifier.py
from dataclasses import dataclass
from enum import Enum


class Label(str, Enum):
    CONFIRMED    = "Confirmed"      # Obj 03 Rank 1
    CODE_ONLY    = "Code only"      # Obj 03 Rank 2
    RUNTIME_ONLY = "Runtime only"   # Obj 03 Rank 3


@dataclass
class ClassificationResult:
    label: Label
    confidence: float
    reason: str


def classify(
    ast_reachable: bool | None,
    langgraph_label: str | None,
    is_config_only: bool,
    dual_confirmed: bool = False,
) -> ClassificationResult:
    """
    Objective 03 classification rules — strict priority order:
    1. LangGraph confirmed + dual-confirmed (CWE AND route both match) → Confirmed (0.98)
    2. LangGraph confirmed exploitation evidence → Confirmed (0.90)
    3. Config issue only → Runtime only
    4. AST unreachable AND not config → Code only (suppress)
    5. AST reachable but probe inconclusive → Code only (pending verification)
    6. Unknown reachability → Code only (conservative)
    """
    if langgraph_label == "Confirmed" and dual_confirmed:
        return ClassificationResult(
            label=Label.CONFIRMED, confidence=0.98,
            reason="SAST sink + DAST probe both confirmed; CWE and route both match.",
        )
    if langgraph_label == "Confirmed":
        return ClassificationResult(
            label=Label.CONFIRMED, confidence=0.90,
            reason="Runtime probe confirmed exploitation evidence in HTTP response.",
        )
    if is_config_only:
        return ClassificationResult(
            label=Label.RUNTIME_ONLY, confidence=0.85,
            reason="No code sink; runtime misconfiguration only (missing headers/CORS/TLS).",
        )
    if ast_reachable is False:
        return ClassificationResult(
            label=Label.CODE_ONLY, confidence=0.95,
            reason="Sink exists in dead code — no HTTP route leads to this function. Suppressed.",
        )
    if ast_reachable is True:
        return ClassificationResult(
            label=Label.CODE_ONLY, confidence=0.70,
            reason="Route is exposed and leads to sink, but runtime probe was inconclusive.",
        )
    return ClassificationResult(
        label=Label.CODE_ONLY, confidence=0.50,
        reason="AST reachability could not be determined; conservative Code only assignment.",
    )
```

---

## Phase 6 — Git Diff Auto-Remediation

**Scoring impact:** Part of the 20-pt criterion. The re-verify step is what judges want to see.

### 6.1 LLM patcher — Sarvam GLM-5.3

```python
# engine/patch_engine/llm_patcher.py
import os
from typing import Optional

_BASE_URL = os.environ.get("SARVAM_BASE_URL", "https://api.sarvam.ai/v2")
_MODEL = os.environ.get("SARVAM_MODEL", "glm5.3")
_KEY = os.environ.get("SARVAM_API_KEY", "")

_SYSTEM = """You are a senior application security engineer.
Generate a minimal, correct unified diff (git diff format) to fix the vulnerability.
Rules: Fix ONLY the vulnerable line(s). Use parameterised queries for SQL,
shlex.quote for shell, os.environ for secrets, bcrypt for passwords,
jwt.decode with algorithm verification for JWT.
Return ONLY the diff — no explanation, no markdown fences."""


def generate_llm_patch(sink_type: str, file_path: str, line: int, code_context: str) -> Optional[str]:
    if not _KEY:
        return None
    from openai import OpenAI
    prompt = f"Fix this {sink_type} vulnerability.\nFile: {file_path}, Line: {line}\n\n```python\n{code_context}\n```\n\nGenerate a unified diff to fix line {line}."
    with OpenAI(base_url=_BASE_URL, api_key=_KEY, timeout=10, max_retries=0) as client:
        resp = client.chat.completions.create(
            model=_MODEL,
            messages=[{"role": "system", "content": _SYSTEM}, {"role": "user", "content": prompt}],
            max_tokens=600, temperature=0, reasoning_effort="low", timeout=10,
        )
    return resp.choices[0].message.content
```

### 6.2 Deterministic patch templates (zero-cost fallback)

```python
# engine/patch_engine/templates.py
PATCH_TEMPLATES: dict[str, str] = {
    "sql_injection": """\
# FIX CWE-89: Parameterised query eliminates SQL injection
# BEFORE: conn.execute("SELECT * FROM users WHERE name='" + username + "'")
# AFTER:
result = conn.execute("SELECT * FROM users WHERE name=?", (username,)).fetchall()
""",
    "xss": """\
# FIX CWE-79: Escape user input before rendering
# BEFORE: return render_template_string(user_input)
# AFTER:
from markupsafe import escape
return str(escape(user_input))
""",
    "command_injection": """\
# FIX CWE-78: subprocess with list args eliminates command injection
# BEFORE: os.popen("grep " + query + " /var/log/app.log")
# AFTER:
import subprocess, shlex
output = subprocess.run(["grep", shlex.quote(query), "/var/log/app.log"],
    capture_output=True, text=True, timeout=5).stdout
""",
    "weak_hash": """\
# FIX CWE-916: bcrypt eliminates weak MD5 password hashing
# BEFORE: hash_pass = hashlib.md5(password).hexdigest()
# AFTER:
import bcrypt
hash_pass = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
""",
    "jwt_weak_secret": """\
# FIX CWE-347: Verify JWT with env secret and algorithm enforcement
# BEFORE: jwt.decode(token, verify=False)
# AFTER:
import os
jwt_secret = os.environ["JWT_SECRET"]
decoded = jwt.decode(token, jwt_secret, algorithms=["HS256"],
    options={"require": ["exp", "iss"]})
""",
    "ssti": """\
# FIX CWE-94: Use static template file instead of render_template_string
# BEFORE: return render_template_string(template % request.url)
# AFTER:
from flask import render_template
return render_template("error_404.html", url=request.url), 404
""",
}


def get_template_patch(sink_type: str):
    return PATCH_TEMPLATES.get(sink_type)
```

---

## Phase 7 — Correlation Graph UI

**Scoring impact:** 10 pts. Confirmed findings ranked first is a hard visual requirement.

### 7.1 Tech stack

- **React + Vite** — fast build, HMR
- **`@xyflow/react`** — interactive node graph with zoom/pan/click
- **`elkjs`** — ELK auto-layout (hierarchical, top-to-bottom attack path)
- **`@tanstack/react-query`** — data fetching with stale-while-revalidate
- **Tailwind CSS** — styling without custom CSS
- **Split-screen:** graph 60% left | detail panel 40% right
- **Target selector:** switch between `flask_demo` and `juice_shop`; all API
  results, finding IDs, stats, and verification requests are scoped to selected `target_id`
- **Label colours:** Confirmed=red (#ef4444), Code only=yellow (#eab308), Runtime only=orange (#f97316)

### 7.2 Graph API response shape

```typescript
// GET http://localhost:8000/api/graph?target_id=flask_demo
interface GraphResponse {
  target_id: "flask_demo" | "juice_shop";
  nodes: Array<{
    id: string;
    type: "endpoint" | "controller" | "sink" | "evidence" | "suppressed";
    position: { x: number; y: number };   // pre-computed ELK layout
    data: {
      label: string;
      finding_label?: "Confirmed" | "Code only" | "Runtime only";
      confidence?: number;
      file?: string;
      line?: number;
      cwe?: string;
      evidence?: string;
    };
  }>;
  edges: Array<{
    id: string; source: string; target: string; animated?: boolean;
  }>;
  stats: {
    target_id: "flask_demo" | "juice_shop";
    total: number;
    confirmed: number;
    code_only: number;
    runtime_only: number;
    suppression_ratio: number;
    cwe_types_covered: string[];   // Obj 01: show ≥4 CWE types
  };
}
```

### 7.3 Live label updates via Server-Sent Events

```typescript
// frontend/src/hooks/useVerification.ts
export function useVerification(findingId: string) {
  const [label, setLabel] = useState<string | null>(null);
  const [probeHistory, setProbeHistory] = useState<any[]>([]);
  const [status, setStatus] = useState<"idle" | "running" | "done">("idle");

  const verify = useCallback(async () => {
    setStatus("running");
    const es = new EventSource(`/api/verify/${findingId}/stream`);
    es.onmessage = (e) => {
      const data = JSON.parse(e.data);
      if (data.label)         setLabel(data.label);       // "Confirmed" flips badge
      if (data.probe_history) setProbeHistory(data.probe_history);
      if (data.done)          { setStatus("done"); es.close(); }
    };
    es.onerror = () => { setStatus("done"); es.close(); };
  }, [findingId]);

  return { label, probeHistory, status, verify };
}
```

---

## Phase 8 — Compliance Translator

**Scoring impact:** 15 pts. References INC-06 directly.

### 8.1 Financial risk calculator

```python
# engine/compliance/risk_calculator.py
# Source: IBM Cost of a Data Breach Report 2024 — India figures
CVSS_TO_PROBABILITY = {
    "CRITICAL": 0.85, "HIGH": 0.65, "MEDIUM": 0.40, "LOW": 0.15, "INFO": 0.05,
}
COST_PER_RECORD_INR = 5_000          # IBM 2024 India benchmark
CYBER_INSURANCE_THRESHOLD_INR = 5_000_000   # ₹50 lakh

# INC-06 reference: 145M records × ₹5,000 × 0.85 = ₹61,625 crore
INC06_REFERENCE = {
    "incident": "2017 Credit Bureau Breach",
    "records_exposed": 145_000_000,
    "estimated_exposure_inr": 145_000_000 * 5_000 * 0.85,
}


def calculate_inr_exposure(finding, records_at_risk: int = 10_000) -> dict:
    prob = CVSS_TO_PROBABILITY.get(finding.severity.upper(), 0.40)
    exposure = records_at_risk * COST_PER_RECORD_INR * prob
    return {
        "breach_probability_pct": int(prob * 100),
        "records_at_risk": records_at_risk,
        "cost_per_record_inr": COST_PER_RECORD_INR,
        "total_exposure_inr": int(exposure),
        "total_exposure_formatted": f"₹{int(exposure):,}",
        "cyber_insurance_impact": exposure > CYBER_INSURANCE_THRESHOLD_INR,
        "ibm_benchmark_source": "IBM Cost of a Data Breach 2024 — India",
        "inc06_reference": INC06_REFERENCE,
    }
```

### 8.2 Compliance mapping (all 4 frameworks)

```python
# engine/compliance/mapping.py
COMPLIANCE_MAP: dict[str, dict] = {
    "CWE-89": {  # SQLi — MANDATORY Obj 01
        "rbi_csf":    "Annex I §4.2 — Baseline Controls: Input Validation & Parameterised Queries",
        "sebi_cscrf": "Domain 5: Application Security — Input Validation Controls",
        "iso_27001":  "A.8.28 — Secure coding; A.8.25 — Secure development lifecycle",
        "dpdp_2023":  "§8(1) — Data fiduciary must implement reasonable security safeguards",
    },
    "CWE-79": {  # XSS — MANDATORY Obj 01
        "rbi_csf":    "Annex I §4.2 — Baseline Controls: Output Encoding",
        "sebi_cscrf": "Domain 5: Application Security — Input Validation Controls",
        "iso_27001":  "A.8.28 — Secure coding",
        "dpdp_2023":  "§8(1) — Reasonable security safeguards",
    },
    "CWE-78": {
        "rbi_csf":    "Annex I §4.2 — Baseline Controls: OS Command Injection Prevention",
        "sebi_cscrf": "Domain 5: Application Security — Secure Coding Standards",
        "iso_27001":  "A.8.28 — Secure coding",
        "dpdp_2023":  "§8(1) — Reasonable security safeguards for personal data processing",
    },
    "CWE-94": {
        "rbi_csf":    "Annex I §4.2 — Baseline Controls: Template Injection Prevention",
        "sebi_cscrf": "Domain 5: Application Security — Secure Coding Standards",
        "iso_27001":  "A.8.28 — Secure coding; A.8.29 — Security testing in development",
        "dpdp_2023":  "§8(1) — Reasonable security safeguards",
    },
    "CWE-347": {
        "rbi_csf":    "Annex I §4.3 — Identity & Access Management: Token Validation",
        "sebi_cscrf": "Domain 3: Identity & Access Management — Authentication Controls",
        "iso_27001":  "A.8.5 — Secure authentication; A.8.3 — Information access restriction",
        "dpdp_2023":  "§8(2) — Obligation to protect personal data from unauthorised access",
    },
    "CWE-502": {
        "rbi_csf":    "Annex I §4.2 — Baseline Controls: Deserialisation Security",
        "sebi_cscrf": "Domain 5: Application Security — Secure Coding Standards",
        "iso_27001":  "A.8.28 — Secure coding",
        "dpdp_2023":  "§8(1) — Reasonable security safeguards",
    },
    "CWE-798": {
        "rbi_csf":    "Annex I §4.3 — Identity & Access Management: Secrets Management",
        "sebi_cscrf": "Domain 3: IAM — Credential Management",
        "iso_27001":  "A.5.17 — Authentication information",
        "dpdp_2023":  "§8(2) — Obligation to protect personal data from unauthorised access",
    },
    "CWE-916": {
        "rbi_csf":    "Annex I §4.3 — Identity & Access Management: Password Storage",
        "sebi_cscrf": "Domain 3: IAM — Password Management",
        "iso_27001":  "A.5.17 — Authentication information; A.8.28 — Secure coding",
        "dpdp_2023":  "§8(1) — Reasonable security safeguards for personal data (passwords)",
    },
}
```

---

## Phase 9 — Demo Polish & Containerisation Verification

### 9.1 5-minute demo script (rehearse exactly)

```
[0:00–0:30] docker compose up --build — show engine, frontend, Flask, and Juice Shop services healthy
            Open http://localhost:3000 directly (NO login screen)
            Select flask_demo; show profile-specific stats and CWE coverage
            Switch to juice_shop; show its Express route map and independent scan counts
            Say: "One pipeline, two language adapters, isolated per-target correlation"

[0:30–1:30] Click "POST /login → login() → jwt.encode() [CWE-347]" node chain
            Show: Merged finding — single record with code (app.py:42) + runtime proof
            Say: "Objective 02 — each vulnerability appears once, code + runtime linked"
            Point out: "Deterministic AST linkage — exact file and line, not LLM guessing"

[1:30–2:30] Click "Verify" on a Code only finding (SSTI in 404 handler)
            Show: LangGraph node progression — probe_generator → runtime_executor → ...
            Show: probe_history — first probe {{7*7}} inconclusive, retry fires
            Show: Response "49" captured → label badge flips "Code only" → "Confirmed" live
            Say: "Objective 03 — Confirmed now ranks first, above all Code only findings"

[2:30–3:30] Click "Auto-Remediate" on a Confirmed SQL injection alert
            Show: Sarvam GLM-5.3 generating context-aware patch (spinner)
            Show: Git diff preview (parameterised query replaces string concat)
            Click "Apply" → patch applied → re-probe fires automatically
            Show: ✅ "Fix Verified — Vulnerability Closed"

[3:30–5:00] Click "Business Risk" tab
            Show: ₹32,50,000 exposure for the JWT finding (HIGH, 10k records)
            Show: RBI CSF, SEBI CSCRF, ISO 27001, DPDP Act 2023 — all 4 frameworks
            Show: "Cyber insurance impact: YES — exceeds ₹50L threshold"
            Reference: "The 2017 credit bureau breach — 145M records — this is what we prevent"
```

### 9.2 Pre-demo checklist

- [ ] `docker compose up --build` completes; both target health checks pass and all four services start
- [ ] `http://localhost:3000` opens directly to Correlation Workbench (no login)
- [ ] Target selector switches between `flask_demo` and `juice_shop`; findings and stats remain target-scoped
- [ ] Both adapters pass route-prefix, helper-scope, parameter-read, and normalized-path fixtures
- [ ] Juice Shop Semgrep/ZAP results are stored and evaluated separately from Flask results
- [ ] Cross-target SAST/DAST findings with matching CWE/path/parameter never correlate
- [ ] Flask profile stats show the controlled fixture's suppression ratio ≥ 70%
- [ ] Flask profile shows ≥ 4 required CWE types; Juice Shop coverage is reported independently
- [ ] Graph renders in < 3 seconds (check browser Performance tab)
- [ ] Confirmed findings appear first in graph and list (Objective 03)
- [ ] At least 1 Confirmed finding with HTTP evidence and confidence score visible
- [ ] Show `/api/orders/42?q=test` resolving to `/api/orders/{param}` in Flask and Express fixtures, including helper scope and query parameter `q`
- [ ] Verify wrong route, wrong parameter, wrong code scope, and wrong CWE each remain unlinked
- [ ] At least 5 Code only findings suppressed (verify suppression ratio ≥ 70%)
- [ ] "Verify" button fires probe, shows retry loop in probe_history, flips label live
- [ ] "Auto-Remediate" shows diff preview (GLM-5.3 or template), applies, re-verifies
- [ ] Business risk panel shows all 4 framework mappings (RBI, SEBI, ISO, DPDP 2023)
- [ ] INC-06 reference visible in business risk panel
- [ ] All probes complete in < 2 seconds (check network tab)
- [ ] No external network calls from probe nodes (check `docker logs mitigata-engine`)
- [ ] `docker compose down && docker compose up --build` still works (idempotent)
- [ ] Flask is reachable at `http://localhost:5050` and Juice Shop at `http://localhost:3001`; both ports are bound to localhost only

### 9.3 Fallback for demo failures

- Pre-record a 90-second screen capture of the full flow as backup
- Keep per-target fixtures in `data/sample/` pre-seeded — either profile works offline
- If Sarvam is unavailable: template patches fire automatically — demo continues
- Have the LangGraph state JSON ready to show in terminal as last resort

---

## Scoring Self-Assessment Checklist

| Criterion | Max | Objective | Self-check | Evidence |
|---|---|---|---|---|
| ≥ 4 CWE types in one common format (SQLi + XSS mandatory) | 30 | Obj 01 | [ ] | Show `stats.cwe_types_covered` in UI |
| Flask and Express adapters implement three-pass route, scope, and parameter mapping | 30 | Obj 02 | [ ] | Show both adapters' `RouteNode` fixtures and per-target `call_graph["stats"]` |
| Findings remain isolated by `target_id` | — | Obj 02 | [ ] | Show cross-target correlation test |
| Each vulnerability appears exactly once (deduplication) | 30 | Obj 02 | [ ] | Show `merged_from` field in finding |
| Runtime finding linked to exact code line | 30 | Obj 02 | [ ] | Show `code_location.file + line` |
| Confirmed/Code only/Runtime only labels assigned | 20 | Obj 03 | [ ] | Show label badges in UI |
| Confirmed findings always ranked first | 20 | Obj 03 | [ ] | Show sorted order in UI + API |
| LangGraph probe fires live and flips label | 25 | Obj 02+03 | [ ] | Show live label animation during demo |
| Flask fixture ≥ 70% SAST alerts unreachable/classified Code only | 20 | Obj 03 | [ ] | Show target-scoped `suppression_ratio` |
| Git diff generated and applied | 20 | Obj 03 | [ ] | Show diff preview in UI |
| Re-verification probe confirms fix | 20 | Obj 03 | [ ] | Show "Fix Verified" status |
| INR financial exposure + INC-06 reference | 15 | — | [ ] | Show ₹ figure with IBM 2024 source |
| All 4 frameworks (RBI + SEBI + ISO + DPDP 2023) | 15 | — | [ ] | Show all 4 framework rows |
| Graph renders in ≤ 3 seconds | 10 | — | [ ] | Check browser Performance tab |
| docker compose up --build works one-command | — | — | [ ] | Demo cold start |
| Complete closed-loop flow in single demo | Bonus | All | [ ] | All 5 demo steps without reload |

---

## Key Decisions Log (v2.0 → v3.3)

| Decision | v2.0 | v3.0 | v3.3 |
|---|---|---|---|
| Classification labels | T1/T2/T3/T4 | **Confirmed/Code only/Runtime only** | Aligned with official Problem 06 statement |
| Label ranking | T1 first | **Confirmed first** — explicit Objective 03 requirement | Problem statement: "rank confirmed issues first" |
| Vulnerability coverage | Implicit | **Explicit: ≥4 of 6 CWE types, SQLi+XSS mandatory** | Objective 01 requirement |
| Merge/dedup | Implicit | **Explicit: each vulnerability appears exactly once** | Objective 02 requirement |
| Compliance frameworks | RBI + SEBI + ISO + DPDP | Same + **INC-06 breach reference** | Problem statement references 2017 credit bureau breach |
| XSS (CWE-79) | In dead_code_helpers | **Promoted to mandatory (Obj 01)** | Problem statement: SQLi AND XSS are mandatory |
| Containerisation | Docker Compose provided | **Hard requirement — all services containerised** | Problem statement: "containerized form" required |
| AST-to-DAST matching | CWE + route text | — | Three passes resolve route prefixes, direct helper scopes, and exact read parameters; all four correlation checks must pass |
| Target/language scope | Flask-only MVP | — | Add OWASP Juice Shop + Express/Node adapter behind shared route schema; isolate scans and findings by target profile |

---

*Build plan version: 3.3 — Mitigata Hackathon Problem 06 (Flagship)*
*Updated: Added OWASP Juice Shop, Express/Node route adapter, target profiles, per-target scan fixtures and isolation, and dual-adapter tests; retained Flask as the reference demo target.*
