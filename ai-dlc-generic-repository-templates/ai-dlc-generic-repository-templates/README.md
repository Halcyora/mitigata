# Mitigata PS5 — SAST & DAST Correlation Engine

> **Mitigata Hackathon — Problem Statement 5 (Flagship)**  
> Hybrid correlation and reachability engine that links HTTP routes to vulnerable code sinks, filters dead-code false positives, and generates verified remediation patches with INR risk and compliance mapping.

## What this does

| Capability | How |
| --- | --- |
| Ingests SAST findings | Parses Semgrep SARIF/JSON (file, line, CWE) |
| Ingests DAST findings | Parses OWASP ZAP alerts JSON (URL, method, parameter) |
| Builds call graph | Python `ast` — deterministic route-to-sink mapper |
| Verifies exploitability | LangGraph stateful agent fires targeted HTTP probes at Docker sandbox |
| Classifies alerts | 4-tier: T1 Confirmed / T2 Reachable / T3 Unreachable / T4 Config |
| Visualises attack path | Interactive React Flow node graph (split-screen, ≤ 3s render) |
| Auto-remediates | One-click Git diff patch + re-verification probe |
| Translates to business risk | INR financial exposure + RBI CSF / SEBI CSCRF / ISO 27001 mapping |

## Quick start

```bash
# 1. Start all containers (target vulnerable app + engine + frontend)
docker compose up --build

# 2. Open the Correlation Workbench
open http://localhost:3000

# 3. (Optional) Re-run Semgrep scan manually
semgrep --config=auto --json target-app/src > data/semgrep-results.json
```

> All containers start automatically. The engine ingests pre-seeded Semgrep and ZAP results on startup and renders the correlation graph within 10 seconds.

## Architecture

```
[Semgrep SARIF]  [ZAP Alerts JSON]
       │                │
       └────────┬───────┘
                ▼
       [Ingestion Pipeline]         — normalise to unified finding schema
                │
                ▼
       [AST Route-to-Sink Mapper]   — Python ast, deterministic call graph
                │
                ▼
       [LangGraph Verification Loop] — targeted HTTP probe → T1/T2/T3/T4
                │
       ┌────────┴────────┐
       ▼                 ▼
[Correlation Graph UI]  [Git Diff Auto-Remediation]
       │                 │
       └────────┬────────┘
                ▼
       [Compliance Translator]      — INR risk + RBI/SEBI/ISO 27001
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for component boundaries and data flows.

## Repository structure

```
├── engine/
│   ├── ingestion/        # Semgrep + ZAP parsers → unified schema
│   ├── ast_mapper/       # Python ast route-to-sink call graph builder
│   ├── langgraph_loop/   # LangGraph stateful verification agent
│   ├── classifier/       # 4-tier T1/T2/T3/T4 classification
│   ├── patch_engine/     # Git diff generation + re-verification
│   └── compliance/       # INR risk + RBI/SEBI/ISO 27001 translator
├── frontend/             # React + React Flow correlation graph UI
├── target-app/           # Sandboxed vulnerable Flask app (demo target)
├── data/                 # Semgrep SARIF + ZAP JSON scan results
├── docker-compose.yml
├── AGENTS.md
├── ARCHITECTURE.md
└── BUILD.md
```

## Key constraints

- All probes use **read-only canary strings** — no destructive payloads
- Probes fire **only on SAST-flagged routes** — no spider crawls
- All probe network calls stay within the **local Docker network**
- AST call graph is built **before** any LLM is invoked

## Problem statement

[docs/PS5-SAST-DAST-Correlation-Engine.md](../../docs/PS5-SAST-DAST-Correlation-Engine.md)
