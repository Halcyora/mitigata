# Build and Validation Guide: Mitigata PS5 — SAST & DAST Correlation Engine

## Supported Development Contract

| Item | Required version | How to verify |
| --- | --- | --- |
| Python | 3.11+ | `python --version` |
| Node.js | 18+ | `node --version` |
| Docker | 24+ with Compose v2 | `docker compose version` |
| Semgrep | Latest stable | `semgrep --version` |
| Git | 2.x | `git --version` |

Supported platforms: Windows 11, macOS, Linux (Ubuntu 22.04+).

## Secrets and Environment Variables

Copy `.env.example` to `.env` and fill in values. Never commit `.env`.

| Variable | Required | Safe default | Secret | Purpose |
| --- | --- | --- | --- | --- |
| `OPENAI_API_KEY` | Yes (patch engine only) | — | ✅ | LLM for patch generation |
| `TARGET_APP_URL` | No | `http://target-app:8080` | No | Docker-internal target URL |
| `ENGINE_PORT` | No | `8000` | No | FastAPI engine port |
| `FRONTEND_PORT` | No | `3000` | No | React frontend port |

The engine must fail clearly on startup if `OPENAI_API_KEY` is absent and the patch engine is invoked.

## Bootstrap

```bash
# Clone the prototype repo
git clone <your-repo-url>
cd mitigata-ps5

# Copy environment template
cp .env.example .env
# Edit .env and add OPENAI_API_KEY

# Build and start all containers
docker compose up --build
```

Expected result: Three containers running (`target`, `engine`, `frontend`). Frontend accessible at `http://localhost:3000`.

## Build, Test, and Run

| Intent | Command | Expected result | When to run |
| --- | --- | --- | --- |
| Start all services | `docker compose up --build` | All 3 containers healthy | First run / after Dockerfile changes |
| Start (no rebuild) | `docker compose up` | All 3 containers healthy | Normal development |
| Stop all services | `docker compose down` | All containers stopped | End of session |
| Run Semgrep scan | `semgrep --config=auto --json target-app/src > data/semgrep-results.json` | JSON written to `data/` | After target-app source changes |
| Run unit tests | `python -m pytest engine/ -v` | All tests pass | After any engine module change |
| Run AST mapper only | `python -m engine.ast_mapper --src target-app/src` | Call graph JSON printed | Debugging call graph |
| Run ingestion only | `python -m engine.ingestion --semgrep data/semgrep-results.json --zap data/zap-alerts.json` | Unified findings JSON printed | Debugging ingestion |
| Run LangGraph loop | `python -m engine.langgraph_loop --finding-id <id>` | Tier classification printed | Debugging probe loop |
| Lint (Python) | `ruff check engine/` | No errors | Before review |
| Lint (TypeScript) | `cd frontend && npm run lint` | No errors | Before review |
| Build frontend | `cd frontend && npm run build` | `dist/` created | Before Docker build |
| Check docs | `git diff --check` | No whitespace errors | Documentation-only changes |

All commands are safe to run locally. No command contacts external systems except `semgrep --config=auto` (downloads rules) and the LLM patch call (requires `OPENAI_API_KEY`).

## Docker Services and Ports

| Service | Internal port | Host port | Notes |
| --- | --- | --- | --- |
| `target` | 8080 | Not exposed | Internal only — reachable by `engine` only |
| `engine` | 8000 | 8000 | FastAPI correlation engine |
| `frontend` | 3000 | 3000 | React UI |

**INVARIANT:** `target:8080` must never be exposed to the host. LangGraph probes reach it via Docker internal network only.

## Test Classification

| Level | Command | Dependencies | What it covers |
| --- | --- | --- | --- |
| Unit | `python -m pytest engine/ -v -m unit` | None (mocked) | AST mapper, classifier, compliance translator, ingestion parser |
| Integration | `python -m pytest engine/ -v -m integration` | Docker containers running | LangGraph loop → probe → tier classification |
| Manual | Open `http://localhost:3000` | All containers running | Graph UI render time, split-screen, re-test button |

## Test Coverage Requirements (PS5 Definition of Done)

| Component | Happy path | Negative path | Edge cases |
| --- | --- | --- | --- |
| Ingestion parser | Valid Semgrep SARIF | Malformed JSON | Empty findings, missing CWE field |
| AST mapper | Route with reachable sink | Route with no sink | Dead function, multi-file call chain |
| LangGraph loop | Canary triggers error response (T1) | Probe blocked (T2) | Timeout at 2s, unreachable route (T3) |
| Classifier | T1 assignment | T3 suppression | All four tiers, boundary conditions |
| Compliance translator | INR calculation for T1 SQLi | T2 finding (no report) | Zero records, max CVSS |
| Patch engine | Patch applied + re-verify passes | Re-verify still exploitable | Invalid diff, patch conflicts |

## Common Failure Modes

| Symptom | Likely cause | Safe next step |
| --- | --- | --- |
| `target` container not reachable from `engine` | Docker network not configured | Check `docker-compose.yml` internal network definition |
| LangGraph probe times out | `target` container not started | `docker compose up target` first |
| Semgrep returns 0 findings | Wrong `--config` or wrong source path | Run `semgrep --config=auto --json target-app/src` and check output |
| AST mapper returns empty call graph | Route decorators not recognised | Check supported decorator patterns in `engine/ast_mapper/patterns.py` |
| Frontend graph does not render | Engine API not responding | Check `http://localhost:8000/health` |
| Patch re-verification still T1 | Patch was insufficient | Review generated diff; LLM may need more context |

## Execution Safety and Agent Controls

| Execution class | Permitted target | Required guardrails |
| --- | --- | --- |
| Semgrep scan | `target-app/src/` (read-only) | Source files are not modified |
| LangGraph probe | `http://target-app:8080` only | Canary strings only; 2s timeout; no external URLs |
| Patch application | `target-app/src/` (write) | Human confirms diff preview in UI before apply |
| LLM call (patch gen) | OpenAI API | Requires explicit user action; no auto-trigger |
| Docker operations | Local containers only | No cloud deployments during demo |

An AI agent must stop and request confirmation before applying a patch, firing a probe outside the local Docker network, or modifying any file outside `target-app/src/`.
