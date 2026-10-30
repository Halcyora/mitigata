# Getting Started: Mitigata PS5 — SAST & DAST Correlation Engine

A practical guide to what is in this workspace, what is relevant to PS5, and how to use it to build the prototype.

## What this workspace contains

| # | Item | Location | Purpose for PS5 |
| --- | --- | --- | --- |
| 1 | PS5 Problem Statement | [docs/PS5-SAST-DAST-Correlation-Engine.md](docs/PS5-SAST-DAST-Correlation-Engine.md) | **Start here.** Full problem statement, mandatory deliverables, scoring breakdown, demo script, and definition of done |
| 2 | `AGENTS.md` template | [ai-dlc-generic-repository-templates/ai-dlc-generic-repository-templates/AGENTS.md](ai-dlc-generic-repository-templates/ai-dlc-generic-repository-templates/AGENTS.md) | Copy into your prototype repo root — tells Copilot the guardrails, scope limits, and safety rules for the engine |
| 3 | `README.md` template | [ai-dlc-generic-repository-templates/ai-dlc-generic-repository-templates/README.md](ai-dlc-generic-repository-templates/ai-dlc-generic-repository-templates/README.md) | Copy and fill in with the project overview, quick-start commands, and architecture entry points |
| 4 | `ARCHITECTURE.md` template | [ai-dlc-generic-repository-templates/ai-dlc-generic-repository-templates/ARCHITECTURE.md](ai-dlc-generic-repository-templates/ai-dlc-generic-repository-templates/ARCHITECTURE.md) | Document your correlation engine boundaries, component ownership, and data flows as you build |
| 5 | `BUILD.md` template | [ai-dlc-generic-repository-templates/ai-dlc-generic-repository-templates/BUILD.md](ai-dlc-generic-repository-templates/ai-dlc-generic-repository-templates/BUILD.md) | Record your real `docker compose up`, `semgrep scan`, and `python -m` commands so Copilot never guesses them |
| 6 | LangGraph knowledge note | [AI-Knowledge-Hub/04-Orchestration/LangGraph.md](AI-Knowledge-Hub/04-Orchestration/LangGraph.md) | Reference for the LangGraph verification loop (PS5 §3.3) — stateful agent orchestration patterns |
| 7 | AI Security Incidents | [AI-Knowledge-Hub/06-Skills-and-Guardrails/Incidents-and-Remedies/CTFS_AI_Agent_Security_Incidents_and_Remedies.md](AI-Knowledge-Hub/06-Skills-and-Guardrails/Incidents-and-Remedies/CTFS_AI_Agent_Security_Incidents_and_Remedies.md) | Reference for probe safety constraints and agent boundary enforcement (PS5 §3.3 constraints) |
| 8 | PS5 Prototype notes | [AI-Knowledge-Hub/08-Prototypes/README.md](AI-Knowledge-Hub/08-Prototypes/README.md) | Record your prototype scope, design decisions, setup instructions, and measured results here |

## What is NOT needed for PS5

- `DEPLOYMENT-OBSERVABILITY.md` — skip until you have a cloud deployment target
- `SYSTEM_INTEGRATION_TEST_PLAN.md` — skip for the hackathon prototype
- `automation-test-feature-guardrails/SKILL.md` — add only once automated test suites exist
- Everything in `AI-Knowledge-Hub/` except `04-Orchestration/LangGraph.md`, `06-Skills-and-Guardrails/Incidents-and-Remedies/`, and `08-Prototypes/` — the rest are research notes on unrelated tools

## How to bootstrap your PS5 prototype repo

1. **Read the problem statement first** — [docs/PS5-SAST-DAST-Correlation-Engine.md](docs/PS5-SAST-DAST-Correlation-Engine.md). Understand the 7 mandatory deliverables and the 4-tier classification system before writing any code.

2. **Create your prototype repo** in VS Code (`File > Open Folder` on a new empty folder, then `git init`).

3. **Copy these four files** flat into the root of your new repo:
   - `README.md` — fill in: "Mitigata PS5 Correlation Engine", what it does, `docker compose up` quick start
   - `AGENTS.md` — fill in purpose/scope; keep all guardrail rules as-is (they enforce the probe safety constraints required by PS5)
   - `ARCHITECTURE.md` — sketch your 7-component architecture (Ingestion → AST Mapper → LangGraph Loop → Classifier → Graph UI → Patch Engine → Compliance Translator)
   - `BUILD.md` — record your actual Semgrep, ZAP, and Python commands as you build them

4. **Build in this order** (matches the PS5 scoring weight):
   - **Step 1 (30 pts):** Unified ingestion pipeline + AST route-to-sink mapper — this is the highest-scoring component; get it working deterministically before touching the UI
   - **Step 2 (25 pts):** LangGraph verification loop — stateful agent that fires targeted probes at the Docker sandbox
   - **Step 3 (20 pts):** 4-tier classifier + Git diff auto-remediation
   - **Step 4 (15 pts):** Mitigata business & compliance translator (INR risk + RBI/SEBI/ISO 27001)
   - **Step 5 (10 pts):** Correlation graph UI (split-screen, interactive nodes, ≤ 3s render)

5. **Demo app setup:** Your sandboxed target application must be in a separate Docker container with at least:
   - 3 HTTP routes (mix of GET/POST)
   - 2 reachable vulnerable sinks (SQL injection or command injection — T1 candidates)
   - 3 unreachable dead-code functions with vulnerabilities (T3 candidates — needed to prove 70%+ noise reduction)
   - 1 runtime config issue (missing security header — T4 candidate)

6. **Open Copilot Chat** — it will automatically read `AGENTS.md`, `README.md`, and any `ARCHITECTURE.md` to ground its behavior for your project.

7. **Update docs in sync with code** — whenever a command, component, or data flow changes, update the corresponding `.md` in the same commit.

## Minimal path (fastest to a working demo)

The bare minimum to get a scoreable PS5 prototype:

```
1. docker compose up  (target vulnerable app + correlation engine)
2. semgrep scan  →  ingest SARIF
3. ZAP targeted probe  →  ingest alerts JSON
4. AST call graph  →  route-to-sink map
5. LangGraph loop  →  T1/T2/T3/T4 classification
6. React Flow graph UI  →  split-screen attack path
7. One-click patch + re-verify  →  "Fix Verified"
8. INR risk + RBI/SEBI/ISO map  →  compliance report
```

Add `README.md` and `AGENTS.md` (even briefly filled in) before your first Copilot session.

## Key constraints to keep in mind (from PS5 §4)

- **Do NOT** build a custom SAST scanner or DAST web crawler — use Semgrep and ZAP
- **Do NOT** feed raw Semgrep + ZAP JSON into an LLM without deterministic AST mapping first
- **Do NOT** run full ZAP spider scans during the demo — targeted probes only
- **Do NOT** use destructive payloads — canary strings only, local Docker network only
- **Do NOT** build login screens or CRUD boilerplate — open directly into the Correlation Workbench
