# PS 5: SAST & DAST Correlation Engine — Link Code Flaws to Proven Runtime Exploits

> **Mitigata Hackathon — Problem Statement 5**  
> Category: Application Security · AI/ML · Compliance Engineering  
> Bonus Tier: **Flagship Problem** (+15 pts)

---

## Table of Contents

1. [Problem Overview](#1-problem-overview)
2. [The Core Challenge](#2-the-core-challenge)
3. [Mandatory Deliverables (Winning Scope)](#3-mandatory-deliverables-winning-scope)
4. [Scope Boundaries — What Must NOT Be Built](#4-scope-boundaries--what-must-not-be-built)
5. [Technical Architecture Requirements](#5-technical-architecture-requirements)
6. [Marking Criteria & Scoring Breakdown](#6-marking-criteria--scoring-breakdown)
7. [4-Tier Alert Classification System](#7-4-tier-alert-classification-system)
8. [Compliance & Business Risk Mapping](#8-compliance--business-risk-mapping)
9. [Demo Expectations](#9-demo-expectations)
10. [Definition of Done](#10-definition-of-done)

---

## 1. Problem Overview

Modern AppSec teams are drowning in **alert fatigue**:

- **SAST tools** (e.g., Semgrep) flag hundreds of *theoretical* code flaws — many of which are completely unreachable in production.
- **DAST tools** (e.g., OWASP ZAP) prove *runtime* weaknesses on live HTTP endpoints — but cannot point developers to the offending line of code.

Neither tool alone is sufficient. Together, without a correlation layer, they produce noise.

**The mission:** Build an automated **Hybrid Correlation and Reachability Engine** that:

- Ingests static source code findings alongside dynamic runtime traces
- Deterministically links each exposed HTTP route to its underlying code sink
- Filters out unreachable false positives
- Generates verified remediation patches mapped to business and compliance risk

---

## 2. The Core Challenge

| Pain Point | SAST Alone | DAST Alone | This Engine |
|---|---|---|---|
| Finds vulnerable code lines | ✅ | ❌ | ✅ |
| Proves runtime exploitability | ❌ | ✅ | ✅ |
| Eliminates dead-code false positives | ❌ | ❌ | ✅ |
| Maps to business/compliance risk | ❌ | ❌ | ✅ |
| Auto-generates verified patches | ❌ | ❌ | ✅ |

---

## 3. Mandatory Deliverables (Winning Scope)

All six components below are **required**. Omitting any one of them risks disqualification from full scoring.

---

### 3.1 Unified Ingestion Pipeline

**What it does:** Parses and normalises findings from two distinct security tool formats into a unified internal schema.

**Inputs:**

| Source | Format | Key Fields |
|---|---|---|
| Semgrep (SAST) | SARIF / JSON | `file`, `line`, `CWE`, `rule_id`, `severity` |
| OWASP ZAP (DAST) | Alerts JSON / HTTP trace logs | `url`, `method`, `parameter`, `evidence`, `cweid` |

**Output:** A normalised finding object with a shared `cwe_id` key enabling cross-tool correlation.

---

### 3.2 Deterministic AST Route-to-Sink Mapper

**What it does:** Uses Python `ast` or `tree-sitter` to build a **call graph** that traces execution from an HTTP route decorator down to a vulnerable code sink.

**Example trace:**

```
@app.post("/login")           ← HTTP Route (entry point)
  └─► authenticate_user()     ← Controller function
        └─► db.execute(query)  ← Vulnerable sink (raw SQL, line 47)
```

**Requirements:**

- Parse route decorators: `@app.get(...)`, `@app.post(...)`, `@router.route(...)`, FastAPI `@router.*`, Flask `@app.route(...)`
- Traverse function call chains across multiple files
- Identify sink patterns: raw SQL execution, `eval()`, `subprocess`, `os.system`, unsafe deserialization, template injection points
- Output a structured call graph (nodes + edges) in a serialisable format (JSON/GraphML)

> ⚠️ **Critical Constraint:** The route-to-sink mapping must be **deterministic** — no LLM guessing. Mathematical linkage must be established *before* any AI layer is invoked.

---

### 3.3 LangGraph Verification Loop

**What it does:** Orchestrates a stateful agent that takes unverified SAST sinks, triggers targeted runtime verification probes against a sandboxed container, and evaluates the HTTP response or stack trace.

**State machine stages:**

```
[UNVERIFIED SINK]
      │
      ▼
[PROBE GENERATOR]  ─── Craft a safe canary HTTP request targeting the exact route
      │
      ▼
[RUNTIME EXECUTOR] ─── Fire probe at sandboxed Docker container
      │
      ▼
[RESPONSE EVALUATOR] ── Analyse HTTP response / stack trace for exploitation evidence
      │
      ├─► Evidence found  ──► [CONFIRMED EXPLOITABLE]
      └─► No evidence     ──► [REACHABLE UNVERIFIED]
```

**Constraints:**
- All probes must be **safe, read-only canary strings** (e.g., `' OR '1'='1` for SQL detection, not `DROP TABLE`)
- Probes fire only on routes already flagged by SAST — no full spider/crawl
- Each probe must complete in **< 2 seconds**
- Probes must be restricted to the **local Docker network** — no external traffic

---

### 3.4 4-Tier Triaged Classification

Every alert must be automatically classified into exactly one of four tiers:

| Tier | Label | Criteria | Action |
|---|---|---|---|
| **T1** | 🔴 Confirmed Exploitable | SAST sink + DAST probe both match; runtime evidence captured | Immediate remediation + auto-patch |
| **T2** | 🟠 Reachable Unverified | Route is exposed, probe was blocked/inconclusive | Manual review required |
| **T3** | 🟡 Unreachable Code | Sink exists in code but no HTTP route leads to it (dead code) | Suppress as false positive |
| **T4** | 🔵 Runtime Config Only | No code flaw; misconfiguration only (missing headers, CORS, TLS) | Config-level fix |

> **Target:** Engine must suppress ≥ 70% of raw SAST alerts as **T3 Unreachable** in the demo repository.

---

### 3.5 Evidence-Backed Correlation Graph UI

**What it does:** Displays an interactive visual node graph linking the full attack path.

**Node types in the graph:**

```
[HTTP Endpoint]  ──►  [Controller Function]  ──►  [Vulnerable Sink (file:line)]  ──►  [Runtime HTTP Proof]
```

**UI Requirements:**

- Interactive node graph (clickable nodes, zoom/pan)
- Clicking a node expands: source code snippet, HTTP request/response evidence, CWE reference, tier classification
- Split-screen layout: attack path graph (left) | code sink + HTTP trace (right)
- Colour-coded by tier (T1=red, T2=orange, T3=yellow, T4=blue)
- Renders full attack path in **≤ 3 seconds** from page load

---

### 3.6 One-Click Git Diff Auto-Remediation

**What it does:** Generates context-aware code patches for confirmed (T1) flaws, applies them, and re-runs the targeted DAST probe to verify the fix closes the vulnerability.

**Workflow:**

```
[T1 Alert Selected]
      │
      ▼
[Patch Generator]  ─── LLM generates a minimal, context-aware code fix
      │
      ▼
[Git Diff Preview] ─── Show unified diff before applying
      │
      ▼
[Apply Patch]      ─── Write fix to source file
      │
      ▼
[Re-run DAST Probe] ── Fire same canary probe against patched container
      │
      ├─► Probe blocked  ──► ✅ "Fix Verified — Vulnerability Closed"
      └─► Probe succeeds ──► ❌ "Fix Insufficient — Re-patch Required"
```

**Requirements:**
- Patch must be a valid unified Git diff (`git diff` format)
- Fix must target the exact sink line identified by the AST mapper
- Re-verification probe must be the same probe used in the original LangGraph loop
- Result status must update live in the UI

---

### 3.7 Mitigata Business & Compliance Translator

**What it does:** Converts confirmed technical vulnerabilities into financial risk exposure (in INR) and maps them to Indian regulatory and international compliance frameworks.

**Financial Risk Output (per confirmed T1 finding):**

| Field | Description |
|---|---|
| `breach_probability` | Estimated likelihood of exploitation (%) |
| `data_records_at_risk` | Estimated number of records exposed |
| `cost_per_record_inr` | Industry benchmark cost per record (₹) |
| `total_exposure_inr` | Calculated financial exposure (₹) |
| `cyber_insurance_impact` | Whether this finding affects insurability or premium |

**Compliance Mapping (per finding):**

| Framework | Relevant Controls |
|---|---|
| **RBI Cyber Security Framework** | Map to applicable CSF control categories |
| **SEBI CSCRF** | Map to applicable CSCRF requirements |
| **ISO 27001:2022** | Map to Annex A controls (e.g., A.8.28 Secure coding) |

---

## 4. Scope Boundaries — What Must NOT Be Built

Violating these boundaries wastes time and **actively reduces your score**.

| ❌ Do NOT Build | Why It's a Trap |
|---|---|
| **Custom SAST scanner** (regex rules, code crawlers) | Semgrep handles this; judges score the correlation engine, not the scanner |
| **Custom DAST web crawler** | ZAP handles this; building one wastes 30+ hours |
| **Blind LLM prompt dumping** | Feeding raw Semgrep + ZAP JSON into a single LLM without deterministic AST mapping causes hallucinations and fails technical scrutiny |
| **Full-app ZAP spider scans during demo** | A standard ZAP spider takes 20+ minutes; only fire targeted sub-second probes on SAST-flagged routes |
| **Destructive payloads** | Never run `DROP TABLE`, OS wipes, or external network scans; canary strings only |
| **Auth, billing, or multi-page CRUD boilerplate** | Skip login screens and settings pages; open directly into the Correlation Workbench |
| **Generic vulnerability dashboards** | A list of CVEs without INR risk quantification and RBI/SEBI mapping scores zero on the business alignment criterion |

---

## 5. Technical Architecture Requirements

### 5.1 Required Tools & Integrations

| Component | Required Tool / Library |
|---|---|
| SAST Scanner | **Semgrep** (output: SARIF or JSON) |
| DAST Scanner | **OWASP ZAP** (output: Alerts JSON) |
| AST Parser | **Python `ast`** module or **tree-sitter** |
| Agent Orchestration | **LangGraph** (stateful graph-based agent) |
| Containerisation | **Docker** (sandboxed target application) |
| Frontend Graph | Any interactive graph library (e.g., React Flow, D3.js, Cytoscape.js) |
| Version Control | **Git** (for diff generation and patch application) |

### 5.2 Target Demo Application

The demo repository must contain:

- At least **3 HTTP API routes** (mix of GET and POST)
- At least **2 reachable vulnerable sinks** (T1 candidates): SQL injection, command injection, or SSTI
- At least **3 unreachable vulnerable functions** (T3 candidates — dead code never called by any route)
- At least **1 runtime config issue** (T4 candidate): missing security header or CORS misconfiguration

### 5.3 Performance Requirements

| Operation | Maximum Allowed Time |
|---|---|
| Full ingestion + correlation graph build | ≤ 10 seconds |
| Single LangGraph verification probe | ≤ 2 seconds |
| UI attack path render | ≤ 3 seconds |
| Patch generation + re-verification | ≤ 15 seconds |

---

## 6. Marking Criteria & Scoring Breakdown

**Total: 100 points + 15 Flagship Bonus = 115 points maximum**

---

### Criterion 1 — Correlation Engine Depth (30 Points)

| Score Band | Description |
|---|---|
| **29–30 pts** | Deterministic AST call graph with CWE cross-referencing and route-to-sink mathematical linkage; zero hallucinated correlations |
| **20–28 pts** | Partial AST mapping with some LLM-assisted guessing; minor false correlations |
| **10–19 pts** | Fuzzy string matching or pure LLM correlation without AST |
| **0–9 pts** | No correlation mechanism; manual mapping only |

**What judges test:** Whether the system can prove — not guess — the exact file and line number of a vulnerability triggered by a specific HTTP parameter.

---

### Criterion 2 — Closed-Loop Runtime Verification (25 Points)

| Score Band | Description |
|---|---|
| **24–25 pts** | Live LangGraph state machine fires targeted probes, captures HTTP evidence, and flips alert status to Verified Exploitable in real time during the demo |
| **16–23 pts** | Probes fire but evidence capture is incomplete or status update is delayed |
| **8–15 pts** | Static JSON upload only; no live probing |
| **0–7 pts** | No runtime verification component |

**What judges test:** Whether the system actively confirms exploitability live — not just displays pre-loaded static results.

---

### Criterion 3 — False-Positive Reduction & Auto-Remediation (20 Points)

| Score Band | Description |
|---|---|
| **19–20 pts** | ≥ 70% of raw SAST alerts suppressed as Unreachable; one-click patch applied; re-verification probe confirms fix; Git diff shown |
| **13–18 pts** | Partial noise reduction (< 70%); patch generated but re-verification missing |
| **6–12 pts** | Text-only remediation advice; no automated patching |
| **0–5 pts** | No noise reduction or remediation |

**What judges test:** Plant dead/unreachable vulnerable functions in the demo repo. The engine must explicitly identify and suppress them.

---

### Criterion 4 — Mitigata Product & Domain Alignment (15 Points)

| Score Band | Description |
|---|---|
| **15 pts** | INR financial risk quantification per finding; explicit RBI CSF, SEBI CSCRF, and ISO 27001 control mapping; cyber insurance impact flagged |
| **10–14 pts** | Partial compliance mapping; financial risk present but generic |
| **5–9 pts** | Generic compliance tags without framework-specific control IDs |
| **0–4 pts** | No business or compliance context |

**What judges test:** Whether the output speaks to a CISO, compliance officer, or cyber insurance underwriter — not just a developer.

---

### Criterion 5 — Demo Speed & Visual Polish (10 Points)

| Score Band | Description |
|---|---|
| **10 pts** | Interactive split-screen; attack path graph renders in ≤ 3 seconds; judges grasp architecture in < 10 seconds; re-test button works live |
| **7–9 pts** | Functional UI but slow render or limited interactivity |
| **4–6 pts** | Basic dashboard; no graph visualisation |
| **0–3 pts** | CLI only or broken demo |

---

### Flagship Bonus — PS 5 Closed-Loop Proof (+15 Points)

Awarded for solving **PS 5 specifically** (the flagship problem) with a complete, closed-loop demonstration:

- SAST finding → AST correlation → LangGraph probe → T1 classification → patch → re-verify → compliance report
- All steps visible and functional in a single live demo flow

---

## 7. 4-Tier Alert Classification System

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ALERT CLASSIFICATION ENGINE                          │
│                                                                         │
│  Raw SAST Alerts (100%)                                                 │
│         │                                                               │
│         ▼                                                               │
│  ┌─────────────────┐                                                    │
│  │  AST Reachability│                                                   │
│  │  Analysis        │                                                   │
│  └────────┬────────┘                                                    │
│           │                                                             │
│    ┌──────┴──────┐                                                      │
│    │             │                                                      │
│  Reachable    Unreachable ──────────────────► T3: Unreachable Code      │
│  (~30%)        (~70%)                         (Suppress as FP)          │
│    │                                                                    │
│    ▼                                                                    │
│  ┌──────────────────┐                                                   │
│  │ LangGraph Runtime│                                                   │
│  │ Verification Loop│                                                   │
│  └────────┬─────────┘                                                   │
│           │                                                             │
│    ┌──────┴──────────────────┐                                          │
│    │             │           │                                          │
│  Exploited   Blocked    Config Only                                     │
│    │             │           │                                          │
│    ▼             ▼           ▼                                          │
│   T1: 🔴       T2: 🟠      T4: 🔵                                      │
│  Confirmed   Reachable   Runtime                                        │
│ Exploitable  Unverified  Config Only                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Compliance & Business Risk Mapping

### 8.1 Regulatory Framework Coverage

#### RBI Cyber Security Framework (CSF)
Applicable to banks, NBFCs, and payment system operators regulated by the Reserve Bank of India.

| Finding Type | RBI CSF Control Area |
|---|---|
| SQL Injection (CWE-89) | Annex I — Baseline Cyber Security Controls |
| Broken Authentication | Annex II — Advanced Measures |
| Sensitive Data Exposure | Circular on Customer Data Protection |
| Missing Security Headers | Network & Application Security |

#### SEBI CSCRF (Cyber Security & Cyber Resilience Framework)
Applicable to stock brokers, depositories, asset management companies, and market infrastructure institutions.

| Finding Type | SEBI CSCRF Domain |
|---|---|
| Input Validation Flaws | Application Security |
| Authentication Weaknesses | Identity & Access Management |
| Data Exposure | Data Security & Privacy |
| Runtime Misconfigurations | Security Configuration Management |

#### ISO 27001:2022 Annex A Controls

| Finding Type | ISO 27001 Control |
|---|---|
| SQL Injection (CWE-89) | A.8.28 — Secure coding |
| XSS (CWE-79) | A.8.28 — Secure coding |
| Broken Auth | A.8.5 — Secure authentication |
| Sensitive Data Exposure | A.8.10 — Information deletion / A.8.11 — Data masking |
| Missing Headers | A.8.23 — Web filtering / A.8.20 — Networks security |

### 8.2 Financial Risk Quantification Formula

```
Total Exposure (INR) = Records at Risk × Cost per Record (INR) × Breach Probability (%)

Where:
  - Records at Risk     = Estimated from endpoint sensitivity and data access patterns
  - Cost per Record     = ₹3,500–₹7,000 (Indian benchmark, IBM Cost of a Data Breach 2024)
  - Breach Probability  = Derived from CVSS score + reachability tier
```

---

## 9. Demo Expectations

### 9.1 Required Demo Flow (Live, ≤ 5 minutes)

```
Step 1 [0:00–0:30]  Open Correlation Workbench directly (no login screen)
                    Show: Unified ingestion of Semgrep + ZAP findings

Step 2 [0:30–1:30]  Navigate the Correlation Graph
                    Show: HTTP endpoint → controller → sink → HTTP proof (split-screen)
                    Show: T3 alerts suppressed (70%+ noise reduction visible)

Step 3 [1:30–2:30]  Live LangGraph Probe (T1 confirmation)
                    Show: Click "Verify" on a T2 alert
                    Show: Probe fires, response captured, status flips to T1 in real time

Step 4 [2:30–3:30]  One-Click Patch & Re-verify
                    Show: Click "Auto-Remediate" on a T1 alert
                    Show: Git diff preview → apply → re-probe → "Fix Verified" status

Step 5 [3:30–5:00]  Business Risk Dashboard
                    Show: INR exposure per finding
                    Show: RBI/SEBI/ISO 27001 control mapping
                    Show: Cyber insurance impact flag
```

### 9.2 Demo Repository Requirements

The target application used in the demo must be:
- Containerised via Docker (runnable with `docker compose up`)
- A simple Python/Node.js web API (Flask, FastAPI, or Express)
- Pre-seeded with a mix of reachable and unreachable vulnerabilities (see §5.2)
- Scannable by Semgrep and ZAP without additional configuration

---

## 10. Definition of Done

A submission is considered complete when **all** of the following are true:

### Functional Completeness
- [ ] Semgrep SARIF/JSON ingested and normalised
- [ ] OWASP ZAP alerts JSON ingested and normalised
- [ ] AST call graph built deterministically from source code
- [ ] Every HTTP route mapped to its downstream sinks (or confirmed as having none)
- [ ] LangGraph verification loop fires targeted probes and updates alert status
- [ ] All alerts classified into T1/T2/T3/T4 tiers
- [ ] ≥ 70% of raw SAST alerts suppressed as T3 in the demo repository
- [ ] Correlation graph UI renders with interactive nodes
- [ ] Git diff patch generated for at least one T1 finding
- [ ] Re-verification probe confirms patch closes the vulnerability
- [ ] INR financial risk calculated for all T1 findings
- [ ] RBI CSF, SEBI CSCRF, and ISO 27001 controls mapped for all T1 findings

### Quality & Performance
- [ ] Full correlation graph builds in ≤ 10 seconds
- [ ] Each verification probe completes in ≤ 2 seconds
- [ ] UI renders in ≤ 3 seconds
- [ ] No external network calls from verification probes
- [ ] No destructive payloads in any probe
- [ ] All probes restricted to local Docker network

### Code Quality
- [ ] No hardcoded secrets or API keys
- [ ] No dead code or debug artifacts
- [ ] Docker Compose file provided for one-command setup
- [ ] README with setup instructions and architecture diagram

---

*Document version: 1.0 — Mitigata Hackathon PS 5*
