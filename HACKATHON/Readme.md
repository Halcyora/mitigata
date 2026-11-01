# Mitigata — SAST/DAST Correlation Engine
### Hackathon Problem 5 · Flagship Challenge

> **One pipeline. Two scanners. Every real vulnerability appears exactly once — with the line of code and live HTTP proof.**

---

## What This Is

Mitigata is a hybrid **SAST + DAST correlation engine** built for Hackathon Problem 06. It scans an application's source code with Semgrep and its running version with OWASP ZAP, then deterministically links the results so each real vulnerability appears once — with both the exact file/line and proof it can be exploited at runtime.

### Overview
This project is an AI-driven hybrid security scanner that bridges Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST).

Traditional security scanners often generate high false-positive rates because they operate in silos. This pipeline solves that challenge by combining precise Code Intelligence (AST), Semantic Code Embeddings (GraphCodeBERT), Static Vulnerability Analysis (Semgrep), and Targeted Dynamic Fuzzing (OWASP ZAP) into a unified correlation loop. Instead of blindly scanning an application, it extracts exact route structures, maps parameter scopes, ranks risks using machine learning, and validates findings dynamically to output verified true positives.

### Key Features
```
Advanced AST Code Intelligence: Multi-pass parser that normalizes dynamic URL patterns (converting framework-specific paths like <int:id> or :id into standardized {param} formats), extracts 1-hop callees, and tracks exact query/body parameters.

- Deep SAST Sink Detection (Semgrep): Automatically scans source code for code sinks, tracks vulnerable variable IDs, and classifies vulnerabilities by CWE (e.g., SQL Injection, XSS).

- Unified Route & Finding Mapping: Correlates static source code blocks, parameter scopes, and route endpoints into a single normalized route graph.

- GraphCodeBERT Scoring Engine: Leverages pre-trained semantic code models to evaluate code similarity and vulnerability likelihood, assigning weighted risk priorities to findings.

- Intelligent Planner: Converts raw static and scored findings into a dynamic, ranked task list to optimize validation workflows.

- Split DAST Testing Passes (OWASP ZAP):

        Focused Pass: Executes targeted payloads on high-risk routes, inputs, and parameters identified by the planner.

        Broad Pass: Performs comprehensive surface crawling and edge-case discovery.

- Multi-Signal Correlation Engine: Validates vulnerabilities by cross-referencing four distinct signals simultaneously: Route Match, Scope Match, Parameter Match, and CWE Match.

- Actionable Reporting: Outputs clean, risk-prioritized vulnerability reports containing verified true positives alongside specific code fixes.
```
---

## Quick Start

### One-command startup (Docker)

```bash
git clone https://github.com/Halcyora/mitigata.git
cd mitigata/HACKATHON
cp .env.example .env          # add SARVAM_API_KEY if you have one
docker compose up --build
```

- **Correlation Workbench** → http://localhost:3000
- **Engine API + Swagger docs** → http://localhost:8000/docs

### Host-mode (Python, no Docker rebuild)

```powershell
# Windows
cd HACKATHON
scripts\start_local_engine.ps1
```

```bash
# Linux / macOS
cd HACKATHON
pip install -r requirements.txt
uvicorn engine.api.main:app --reload --port 8000
```

### Offline demo (pre-seeded fixtures)

```bash
python scripts/load_sample.py configs/flask_demo.yaml
python scripts/load_sample.py configs/juice_shop.yaml
```

---

## Target Profiles

Two selectable targets — select one per scan run:

| Profile | App | Language | Port | Role |
|---|---|---|---|---|
| `flask_demo` | [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | Python / Flask | 5050 | Baseline, controlled fixtures, fast offline demo |
| `juice_shop` | [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | JavaScript / Express | 3001 | Second-language validation on a real app |

Fetch targets before first run:

```powershell
scripts\fetch_targets.ps1
scripts\fetch_flask_wheels.ps1   # pre-built Flask wheels for offline installs
```

---

## Running Scans

```bash
# SAST only
python scripts/run_scan.py configs/flask_demo.yaml

# SAST + targeted DAST (5-minute ZAP budget)
python scripts/run_scan.py configs/flask_demo.yaml --dast

# Juice Shop
python scripts/run_scan.py configs/juice_shop.yaml --dast

# Evaluate against ground truth
python scripts/evaluate.py configs/flask_demo.yaml
```

---

## Repository Structure

```
HACKATHON/
├── configs/
│   ├── flask_demo.yaml          # Python/Flask profile: source, URL, Semgrep packs
│   └── juice_shop.yaml          # JavaScript/Express profile
├── targets/
│   ├── vulnerable_flask/        # we45 Flask target + dead_code_helpers.py
│   └── juice-shop/              # OWASP Juice Shop checkout
├── data/
│   ├── ground_truth/            # per-target verified answer keys
│   ├── raw/                     # live scan output (semgrep/zap/verification JSON)
│   └── sample/                  # pre-seeded offline fixtures
├── engine/
│   ├── adapters/                # Flask + Express RouteAdapter implementations
│   ├── api/                     # FastAPI: /api/graph, /api/verify, /api/patch, /api/compliance
│   ├── ast_mapper/              # three-pass route mapper, sink detector, call graph, merger
│   ├── classifier/              # Confirmed / Code only / Runtime only + risk scoring
│   ├── code_intelligence/       # GraphCodeBERT shadow ranker (advisory)
│   ├── compliance/              # INR risk calculator + RBI/SEBI/ISO/DPDP mapping
│   ├── dast_planner/            # ScanPlan / ScanTask / ScanEvent + ZAP rule mapping
│   ├── ingestion/               # semgrep_parser, zap_parser, correlator, deduplication, schema
│   ├── patch_engine/            # Sarvam GLM-5.3 → template fallback patch generator
│   ├── scan_manager/            # scan job lifecycle, event store, history, state
│   └── verification/            # bounded runtime probe workflow (SSE stream)
├── frontend/
│   └── src/
│       ├── App.tsx
│       ├── components/
│       │   ├── CorrelationGraph.tsx   # React Flow + ELK layered layout
│       │   ├── BusinessRiskPanel.tsx  # INR exposure + compliance frameworks
│       │   └── PlannerPanel.tsx       # DAST plan preview + task queue
│       └── hooks/
│           └── useVerification.ts     # SSE hook for live label flip
├── tests/                       # pytest suite (14 test modules)
├── scripts/                     # run_scan, load_sample, evaluate, zap_api_driver, check_sarvam
├── docker-compose.yml
├── requirements.txt
└── AGENTS.md
```

---

## Architecture Overview

```
Browser :3000
    │
    ▼
React Frontend (Correlation Workbench)
    │   GET /api/graph?target_id=flask_demo
    ▼
FastAPI Engine :8000
    ├── semgrep_parser  →  UnifiedFinding[] (SAST)
    ├── zap_parser      →  UnifiedFinding[] (DAST)
    ├── Flask/Express adapter
    │     Pass 1: route declarations + prefix resolution → normalized RouteNode[]
    │     Pass 2: handler + one-hop helper scopes       → CodeScope[]
    │     Pass 3: request parameter reads               → ParameterRead[]
    ├── DAST planner: ScanPlan + ScanTask queue (targeted → broad)
    │     advisory GraphCodeBERT ranking for ambiguous candidates
    ├── correlator: target_id + CWE + route + scope + parameter → Confirmed
    ├── classifier: Confirmed / Code only / Runtime only + risk score
    └── ELK layout → GraphResponse {nodes, edges, stats}
    │
    ▼
Docker internal network
    ├── Flask target  :5050  (internal only)
    └── Juice Shop    :3001  (internal only)
```

Full architecture diagrams: [`docs/P06-Architecture.md`](docs/P06-Architecture.md)

---

## Architecture Diagram

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                      1. TARGET APP (Flask / Juice Shop)                      │
└──────────────────────┬───────────────────────────────┬───────────────────────┘
                       │                               │
                       ▼                               ▼
    ┌──────────────────────────────────┐    ┌──────────────────────────────────┐
    │     2. AST ENGINE (Code Intel)   │    │     3. SEMGREP SCAN (SAST)       │
    ├──────────────────────────────────┤    ├──────────────────────────────────┤
    │ • Pass 1: Route & Prefix (Spec)  │    │ • Deep Code Sink Detection       │
    │ • Pass 2: 1-Hop Callees (CPG)    │    │ • CWE Classification (e.g., CWE-89)│
    │ • Pass 3: Param Extractor (Resp) │    │ • Initial Vulnerable Variable IDs│
    └──────────────────┬───────────────┘    └──────────────────┬───────────────┘
                       │                                       │
                       └───────────────┬───────────────────────┘
                                       │
                                       ▼
    ┌──────────────────────────────────────────────────────────────────────────┐
    │                     4. UNIFIED ROUTE & FINDING MAPPER                    │
    │  • Normalizes URLs (e.g., /api/orders/{param})                           │
    │  • Maps SAST findings and parameter scopes to specific code blocks       │
    └─────────────────────────────────┬────────────────────────────────────────┘
                                      │
                                      ▼
    ┌──────────────────────────────────────────────────────────────────────────┐
    │                     5. GRAPHCODEBERT SCORING ENGINE                      │
    │  • Evaluates semantic code similarity and vulnerability likelihood       │
    │  • Assigns risk weights to prioritized findings                          │
    └─────────────────────────────────┬────────────────────────────────────────┘
                                      │
                                      ▼
    ┌──────────────────────────────────────────────────────────────────────────┐
    │                       6. INTELLIGENT PLANNER                             │
    │  • Generates a dynamic, ranked task list for validation & fuzzing        │
    └─────────────────────────────────┬────────────────────────────────────────┘
                                      │
               ┌──────────────────────┴──────────────────────┐
               ▼                                             ▼
    ┌──────────────────────────────────┐    ┌──────────────────────────────────┐
    │     7a. ZAP FOCUSED PASS         │    │     7b. ZAP BROAD PASS           │
    ├──────────────────────────────────┤    ├──────────────────────────────────┤
    │ • Targeted payloads on high-risk │    │ • Comprehensive app crawl        │
    │   routes, inputs & params        │    │ • Surface discovery & edge cases │
    └──────────┬───────────────────────┘    └──────────┬───────────────────────┘
               │                                       │
               └──────────────────────┬──────────────────────┘
                                      │
                                      ▼
    ┌──────────────────────────────────────────────────────────────────────────┐
    │                       8. CORRELATION ENGINE                              │
    │  ✅ Route Match:    ZAP URL path == AST Normalized Route                 │
    │  ✅ Scope Match:    Vulnerable file/line inside 1-hop scope              │
    │  ✅ Param Match:    Attacked query/body param == AST extracted param     │
    │  ✅ CWE Match:      DAST behavior aligns with SAST vulnerability type    │
    └─────────────────────────────────┬────────────────────────────────────────┘
                                      │
                                      ▼
    ┌──────────────────────────────────────────────────────────────────────────┐
    │                       9. CLASSIFICATION & REPORT                         │
    │  🎯 Verified True Positives  │  📊 Risk-Prioritized Findings  │  🛡️ Fixes│
    └──────────────────────────────────────────────────────────────────────────┘
```


---
## API Reference

| Endpoint | Description |
|---|---|
| `GET /api/graph?target_id=...` | Full correlation graph — nodes, edges, stats. Cached 10 s. |
| `GET /api/verify/{id}/stream?target_id=...` | SSE stream — live label flip Code only → Confirmed |
| `POST /api/patch` | Generate unified diff patch (Sarvam GLM-5.3 → template fallback) |
| `POST /api/patch/apply` | Apply approved patch + invalidate graph cache |
| `GET /api/compliance?target_id=...` | INR exposure + RBI/SEBI/ISO 27001/DPDP 2023 per finding |
| `GET /api/export/sarif?target_id=...` | SARIF 2.1 export; `fail_on_confirmed_high=true` returns HTTP 409 for CI gates |
| `GET /api/planner?target_id=...` | DAST scan plan preview (does not start a scan) |
| `POST /api/scans` | Start a SAST or DAST scan job |
| `GET /api/scans/latest?target_id=...` | Latest scan job status + phase counts |
| `GET /api/scans/compare?target_id=...` | Diff two consecutive scans: new / fixed / still-open |
| `GET /health` | Docker healthcheck |
| `GET /docs` | Swagger UI (auto-generated) |

---

## Finding Labels

| Label | Meaning | Rank |
|---|---|---|
| 🔴 **Confirmed** | SAST code evidence + DAST runtime proof; all correlation checks pass | 1 — Fix immediately |
| 🟡 **Code only** | SAST finding did not pass the strict correlation gate; AST reachability retained separately | 2 — Review |
| 🟠 **Runtime only** | DAST finding not consumed by a confirmed pair | 3 — Investigate |

> Confirmed findings always rank first in every view, API response, and SARIF export.

---

## Correlation Gate

A SAST/DAST pair is labelled **Confirmed** only when **all** of the following agree:

1. `target_id` — same profile; findings from different targets never correlate
2. `cwe_id` — same CWE number (normalised: `CWE-079` == `CWE-79`)
3. Normalised route — DAST URL path matches the route template (e.g. `/api/orders/{param}`)
4. HTTP method — must match when the DAST scanner reports one
5. Code scope — SAST `file:line` falls within the handler or a direct one-hop helper scope
6. Attacked parameter — DAST parameter name is read by the route; source kind must match when supplied

A CWE-only or route-only match is **never** sufficient.

---

## Vulnerability Coverage

| CWE | Type | Mandatory | Status |
|---|---|---|---|
| CWE-89 | SQL Injection | ✅ | Detected + correlated |
| CWE-79 | XSS | ✅ | Detected + correlated |
| CWE-78 | Command Injection | Pick ≥ 2 | Detected |
| CWE-22 | Path Traversal | Pick ≥ 2 | Detected |
| CWE-601 | Open Redirect | Pick ≥ 2 | Detected |
| CWE-798 | Hard-coded Secrets | Pick ≥ 2 | Detected |
| CWE-94 | SSTI | Bonus | Detected + live probe |
| CWE-347 | JWT Weak Secret | Bonus | Detected |
| CWE-502 | Insecure Deserialisation | Bonus | Detected |
| CWE-916 | Weak Hash | Bonus | Detected |

---

## Runtime Verification

Click **Verify** on any *Code only* finding in the UI to start a bounded probe:

1. **probe_generator** — selects a safe canary payload for the sink type (e.g. `{{7*7}}` for SSTI)
2. **runtime_executor** — fires an `httpx` request to the configured local target origin; 2 s hard timeout; no external traffic
3. **response_evaluator** — checks response for sink-specific evidence signals
4. **retry_evaluator** — retries once with a variant payload if the first attempt is inconclusive

A positive result flips the label to **Confirmed** live in the UI via SSE and persists the result to `data/raw/<target>-verification.json`.

Non-probeable sinks (hardcoded secrets, JWT weak secrets, weak hashes, insecure deserialisation) remain `UNVERIFIED` — no safe runtime signal exists for them.

---

## Patch Generation

Click **Auto-Remediate** on a Confirmed finding:

1. Engine reads ±40 lines of source context around the sink
2. Calls **Sarvam GLM-5.3** (`SARVAM_API_KEY` required) — returns a unified diff
3. Falls back to **deterministic CWE-mapped templates** if the LLM is unavailable or returns invalid output
4. Shows a Git diff preview in the UI before applying
5. Applies the patch and re-runs the same canary probe to verify the fix

Set `SARVAM_API_KEY` in `.env`. Run `python scripts/check_sarvam.py` to verify the key.

---

## Compliance & Business Risk

`GET /api/compliance?target_id=flask_demo` returns per-finding:

- **INR financial exposure** — `records × ₹5,000/record × breach_probability` (IBM Cost of a Data Breach 2024, India benchmark)
- **RBI Cyber Security Framework** — Annex I / Annex II control mapping
- **SEBI CSCRF** — Application Security + IAM domain mapping
- **ISO 27001:2022** — Annex A control mapping (A.8.28 Secure coding, etc.)
- **DPDP Act 2023** — §8(1) / §8(2) obligation mapping
- **Cyber insurance impact flag** — `true` when exposure exceeds ₹50 L threshold

---

## DAST Planner & GraphCodeBERT

Before ZAP runs, the engine builds a `ScanPlan`:

- Maps SAST findings to route + parameter + ZAP rule candidates
- Assigns priority classes: `ROUTE_SCOPE_MATCH` → `HELPER_SCOPE_MATCH` → `INPUT_EVIDENCE_INCOMPLETE` → `BROAD_COVERAGE`
- When `GRAPHCODEBERT_MODE=ON`, the **GraphCodeBERT shadow ranker** (`microsoft/graphcodebert-base`, pinned revision) ranks ambiguous candidates by cosine similarity — **advisory only**, never overrides the correlation gate
- Produces targeted tasks (15 s ceiling each) and broad fallback tasks (5 s ceiling each) within a 5-minute ZAP budget

Set `GRAPHCODEBERT_MODE=OFF` (default) to skip the model step entirely without affecting correlation.

---

## Scan Comparison & SARIF Export

```bash
# Compare latest vs previous scan
GET /api/scans/compare?target_id=flask_demo
# → {new: [...], fixed: [...], still_open: [...]}

# SARIF export
GET /api/export/sarif?target_id=flask_demo

# CI gate — returns HTTP 409 when a Confirmed HIGH/CRITICAL finding exists
GET /api/export/sarif?target_id=flask_demo&fail_on_confirmed_high=true
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TARGET_PROFILE` | `flask_demo` | Active target profile for Docker Compose |
| `TARGETS_ROOT` | `/targets` | Volume mount path for target source trees |
| `SARVAM_API_KEY` | _(empty)_ | Sarvam Token Factory key — leave blank for template patches |
| `SARVAM_BASE_URL` | `https://api.sarvam.ai/v2` | Sarvam API base URL |
| `SARVAM_MODEL` | `glm5.3` | Sarvam model name |
| `GRAPHCODEBERT_MODE` | `OFF` | `ON` to enable advisory GraphCodeBERT ranking |
| `MITIGATA_CONFIG_DIR` | `configs/` | Override config directory |

Copy `.env.example` to `.env` and fill in values. **Never commit `.env`.**

---

## Tests

```bash
cd HACKATHON
pip install -r requirements.txt
pytest tests/ -v
```

14 test modules covering: ingestion, AST mapper, correlator, classifier, verification workflow, DAST planner, scan manager, patch engine, API graph, ZAP driver, parsers e2e, GraphCodeBERT shadow ranker, and incremental correlation.

---

## Network Isolation

```
Host machine
  ├── :3000  → frontend  (public network)
  ├── :8000  → engine    (public + internal network)
  ├── :5050  ✗  (Flask target — internal only, not reachable from host)
  └── :3001  ✗  (Juice Shop — internal only, not reachable from host)
```

All verification probes route through the Docker internal network. No probe ever leaves the local machine.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/P06-Architecture.md`](docs/P06-Architecture.md) | Full Mermaid architecture diagrams — data flow, component deep-dives, schemas, API contract |
| [`docs/P06-SAST-DAST-Correlation-Engine.md`](docs/P06-SAST-DAST-Correlation-Engine.md) | Problem statement, three objectives, scoring criteria, definition of done |
| [`docs/P06-Build-Plan.md`](docs/P06-Build-Plan.md) | Phase-by-phase build plan, FR-to-component mapping, bonus feature tracking |
| [`docs/P06-PRD.md`](docs/P06-PRD.md) | Product requirements — source of truth |
| [`engine/README.md`](engine/README.md) | Engine package internals — route mapping, verification, classifier, patch, API |
| [`AGENTS.md`](AGENTS.md) | AI agent context and task history |

---

*Mitigata · Hackathon Problem 06 · Flagship Challenge*
*Inspired by the 2017 Credit Bureau Breach — INC-06 — 145 million records*
