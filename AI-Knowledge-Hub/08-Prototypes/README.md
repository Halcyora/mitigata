# 08-Prototypes — PS5 Correlation Engine

Record your prototype scope, design decisions, setup instructions, and measured results here as you build.

---

## Prototype: Mitigata PS5 SAST & DAST Correlation Engine

**Problem Statement:** [PS5 — SAST & DAST Correlation Engine](../../docs/PS5-SAST-DAST-Correlation-Engine.md)  
**Status:** In progress  
**Target:** 115 points (100 base + 15 flagship bonus)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CORRELATION ENGINE                               │
│                                                                     │
│  [Semgrep SARIF]  [ZAP Alerts JSON]                                │
│         │                │                                          │
│         └────────┬───────┘                                          │
│                  ▼                                                   │
│         [Ingestion Pipeline]  ←── normalise to unified schema       │
│                  │                                                   │
│                  ▼                                                   │
│         [AST Route-to-Sink Mapper]  ←── Python ast / tree-sitter   │
│                  │                                                   │
│                  ▼                                                   │
│         [LangGraph Verification Loop]  ←── targeted probe           │
│                  │                                                   │
│                  ▼                                                   │
│         [4-Tier Classifier]  T1 / T2 / T3 / T4                     │
│                  │                                                   │
│         ┌────────┴────────┐                                         │
│         ▼                 ▼                                         │
│  [Correlation Graph UI]  [Git Diff Auto-Remediation]               │
│         │                 │                                         │
│         └────────┬────────┘                                         │
│                  ▼                                                   │
│         [Compliance Translator]  ←── INR risk + RBI/SEBI/ISO 27001 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Component Decisions

| Component | Technology Choice | Rationale |
| --- | --- | --- |
| SAST Scanner | Semgrep | Required by PS5; outputs SARIF/JSON with file, line, CWE |
| DAST Scanner | OWASP ZAP | Required by PS5; outputs alerts JSON with URL, method, parameter |
| AST Parser | Python `ast` module | Built-in, deterministic, works natively on Python target app |
| Agent Orchestration | LangGraph | Required by PS5; stateful graph maps directly to probe loop |
| Target App | **we45/Vulnerable-Flask-App** (real benchmark) | Industry-standard OWASP-aligned Python Flask app; no custom app needed; judges recognise it |
| Frontend Graph | React Flow | Interactive node graph, zoom/pan, click-to-expand, fast render |
| Backend API | FastAPI | Lightweight, async, easy to integrate with LangGraph |
| Containerisation | Docker Compose | One-command setup for judges; isolates target app from engine |

> **Why not build a custom vulnerable app?**  
> Using a real benchmark app (we45/Vulnerable-Flask-App) is more credible, saves time, and is what real AppSec teams do. The judges score the correlation engine, not the target app. See [PS5-Build-Plan.md](../docs/PS5-Build-Plan.md) §1.1 for the full rationale.

---

## Target App — we45/Vulnerable-Flask-App Vulnerability Map

Source: [github.com/we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App)

| Route | Vulnerability | CWE | Expected Tier |
| --- | --- | --- | --- |
| `POST /login` | Raw SQL: `db.execute("SELECT..."+username)` | CWE-89 | T1 🔴 |
| `GET /users` | SQLi via query param | CWE-89 | T1 🔴 |
| `POST /cmd` | `os.system(user_input)` | CWE-78 | T1 🔴 |
| `POST /template` | Jinja2 SSTI | CWE-94 | T2 🟠 |
| Various helper functions | SQLi/eval not wired to any route | CWE-89/95 | T3 🟡 |
| Missing response headers | No `X-Content-Type-Options` | — | T4 🔵 |

**Noise reduction:** The app has more vulnerable helper functions than exposed routes — 70%+ T3 suppression is achievable without any custom seeding.

---

## Setup Instructions

```bash
# Clone the prototype repo
git clone <your-repo-url>
cd mitigata-ps5

# Start all containers (target app + correlation engine + frontend)
docker compose up --build

# Run Semgrep scan against target app source
semgrep --config=auto --json target-app/src > data/semgrep-results.json

# Run ZAP targeted probes (triggered automatically by engine after AST mapping)
# Or manually: python -m engine.zap_probe --url http://localhost:8080

# Open the Correlation Workbench
open http://localhost:3000
```

---

## Performance Targets

| Operation | Target | Measured |
| --- | --- | --- |
| Full ingestion + correlation graph build | ≤ 10s | TBD |
| Single LangGraph verification probe | ≤ 2s | TBD |
| UI attack path render | ≤ 3s | TBD |
| Patch generation + re-verification | ≤ 15s | TBD |

---

## Results and Evidence

Record measured outcomes here as you test:

- Noise reduction achieved: TBD (target ≥ 70% T3 suppression)
- T1 alerts confirmed with HTTP evidence: TBD
- Patches verified as closed: TBD
- Compliance mappings generated: TBD

---

## Known Risks and Open Questions

- `{{OPEN_QUESTION}}` — Which ZAP API mode (daemon vs Docker image) gives fastest targeted probe response?
- `{{OPEN_QUESTION}}` — Does tree-sitter need to replace Python `ast` for multi-file call graph traversal?
- `{{OPEN_QUESTION}}` — LangGraph streaming — SSE or WebSocket for live UI state updates?
