# SAST-DAST Correlator

## Current phase: targets, scanners, and Docker

The current codebase contains Python and JavaScript route parsers. Phase 1 adds
pinned upstream targets, per-target profiles, and a Docker Compose network that
keeps intentionally vulnerable apps isolated from host access.

From this directory, in PowerShell, fetch the target sources and start the
engine, dashboard, and target applications:

```powershell
.\scripts\fetch_targets.ps1
.\scripts\fetch_flask_wheels.ps1
docker compose up --build
```

Compose builds and starts the Flask reference app and OWASP Juice Shop. The
targets bind only to host loopback ports 5050 and 3002 by default. Scanner images are
configured as on-demand Compose services: Semgrep can read target source but
cannot reach the target network; ZAP can reach only the isolated target
network. Do not expose these intentionally vulnerable target containers to
untrusted networks.

The Compose API container cannot launch scanner jobs because it has no access to
the host Docker daemon. To use the dashboard's **Run SAST** and **Run targeted +
broad DAST** actions, use the host API mode below: it leaves the target apps and
scanners in Docker and runs FastAPI on the host where Docker Compose is available.

### Run the API and GraphCodeBERT in the host Python environment

Use this path when the engine Docker image cannot be rebuilt (for example, when
the Docker build environment cannot validate the package index certificate).
Docker still provides the isolated Flask and Juice Shop targets and the
containerized scanners; FastAPI and GraphCodeBERT run in your local Python
environment. The local launcher stops the Compose engine/frontend services,
starts only the two targets, and sets their loopback URLs for API verification.
It does not build the engine image.

From this directory in PowerShell, prepare the Python environment once:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Fetch the pinned target sources and Flask wheelhouse if they are not present,
then start the local API:

```powershell
.\scripts\fetch_targets.ps1
.\scripts\fetch_flask_wheels.ps1
.\scripts\start_local_engine.ps1
```

The first planner request downloads the pinned GraphCodeBERT model into the
host Hugging Face cache if it is not cached already. The model runs on CPU and
planner status reports download or inference failures; it does not substitute
synthetic scores. Open a second terminal to start the UI from the host:

```powershell
cd frontend
npm install
npm run dev
```

The UI is at [http://localhost:5173](http://localhost:5173). The host API is at
[http://localhost:8000](http://localhost:8000). For bounded DAST, run the scan
CLI from the project root in a third terminal; ZAP remains isolated in Docker
and continues to use the Compose-only target network:

```powershell
.\.venv\Scripts\python.exe scripts/run_scan.py configs/flask_demo.yaml --dast --dast-minutes 5
```

The five-minute limit covers ZAP startup, route tests, alert collection, and
cleanup after the target is healthy and the plan is ready. Semgrep and planner
time are reported separately. This CLI path does not require the engine image.

Run a real SAST scan, or SAST followed by Semgrep-guided targeted DAST and
broader route coverage, from this directory:

```powershell
python -m pip install -r requirements.txt
python scripts/run_scan.py configs/flask_demo.yaml
python scripts/run_scan.py configs/flask_demo.yaml --dast
python scripts/run_scan.py configs/juice_shop.yaml --dast
python scripts/run_scan.py configs/flask_demo.yaml --dast --dast-minutes 3
```

The first scan pulls the pinned scanner images. Semgrep also needs outbound
network access to resolve configured rule packs. If your network inspects TLS
and Semgrep cannot validate its certificate chain, set `MITIGATA_CA_CERT_PATH`
to a PEM CA certificate trusted by your machine; the runner mounts it read-only
for Semgrep and keeps certificate verification enabled. In the local-engine
setup, put `MITIGATA_CA_CERT_PATH=C:\path\to\trusted-ca.pem` in `.env` before
running `scripts/start_local_engine.ps1`, or set the variable in PowerShell
before launching the API. For DAST, the AST route
inventory is joined to normalized Semgrep findings by target-relative file and
line scope. Explainable priority tiers schedule mapped route/method/CWE rule
tasks first; ZAP enables only the mapped scanners for those tasks, then tests
the route inventory with the same six verified security scanners used by the
initial rule map. Each route is seeded directly into ZAP's site tree and
active-scanned within the exact selected-target context; per-task timeouts leave
budget for later routes.

The initial rule map covers CWE-22, CWE-78, CWE-79, CWE-89, and CWE-601 using
scanner IDs verified in the pinned ZAP image. Unsupported input bindings (JSON
body and headers) are recorded in the plan rather than fabricated. DAST has a
1-30 minute budget (default 5); task states, priorities, route evidence, and
coverage are written to `data/raw/<target>-scan-plan.json`, while standard
ZAP alerts and task outcomes are written to `data/raw/<target>-zap.json`.
Untested routes are reported as incomplete, not safe. Scanner failures stop the
command instead of silently substituting sample or placeholder findings.

The engine image loads the pinned `microsoft/graphcodebert-base` encoder locally
for advisory ranking of deterministically mapped ambiguous route candidates.
`GRAPHCODEBERT_MODE=OFF` disables this step; model loading or inference failures
are surfaced in planner status and never replaced with generated scores. The
encoder compares a finding/route query with each candidate's source context by
cosine similarity and a graph-guided attention mask built from lexical identifier
def/use links. These links approximate data flow and are not a taint analysis.
Scores are uncalibrated and are not vulnerability
probabilities. The five-minute DAST clock begins after the selected target is
healthy and the scan plan is ready; it includes ZAP startup, route tests, alert
collection, and cleanup. Targeted and broad route tasks are capped at 15
seconds. Semgrep and planning time are listed separately from
ZAP execution time. The engine image preloads model weights during its build;
the local Python CLI downloads the same pinned weights on first use if they are
not already in the Hugging Face cache, before starting the DAST clock.

The Flask wheelhouse is downloaded on the host using its trusted certificate
store, then installed offline in the container. This avoids weakening TLS
verification in the legacy target's container build.

See [targets/README.md](targets/README.md) for upstream revisions and isolation
details. The profiles are [configs/flask_demo.yaml](configs/flask_demo.yaml)
and [configs/juice_shop.yaml](configs/juice_shop.yaml).

The Flask upstream is an old Python 2 application. Its source remains unchanged
and is run through a separate Python 3 compatibility overlay in
`targets/vulnerable_flask`; this is only an isolated test target, not a
production service. Target source checkouts are ignored by Git and pinned by
`scripts/fetch_targets.ps1`.

## Planned project structure

```
sast-dast-correlator/
├── README.md                      # how to run, demo steps
├── requirements.txt               # fastapi, uvicorn, pydantic, zaproxy, streamlit, pytest, pyyaml, requests
├── docker-compose.yml             # zap, juice-shop, flask-target, (optional) app
├── .env.example                   # ZAP_API_KEY, ZAP_URL, LLM_API_KEY (optional)
│
├── configs/                       # Step 1: application profiles
│   ├── flask_demo.yaml            # source_dir, target_url, language, semgrep packs, excludes
│   └── juice_shop.yaml
│
├── targets/                       # apps under test (your own, local only)
│   ├── vulnerable_flask/
│   │   ├── app.py
│   │   ├── Dockerfile
│   │   └── GROUND_TRUTH.md        # list of known vulns, used for your accuracy table
│   └── juice-shop/                # git clone of OWASP Juice Shop (source for SAST)
│
├── sastdast/                      # main Python package
│   ├── __init__.py
│   ├── config.py                  # loads YAML, picks adapter by language
│   ├── pipeline.py                # runs steps 2 to 7 in order, saves results
│   │
│   ├── scanners/                  # Steps 2 and 4
│   │   ├── semgrep_runner.py      # runs semgrep, returns raw JSON
│   │   └── zap_runner.py          # spider, ajax spider, active scan, alerts
│   │
│   ├── adapters/                  # Step 3: language-specific, pluggable
│   │   ├── base.py                # RouteAdapter interface: discover_routes(source_dir)
│   │   ├── flask_adapter.py       # Python ast based
│   │   ├── express_adapter.py     # calls the Node script, parses its JSON
│   │   └── js/
│   │       └── extract_routes.js  # TypeScript Compiler API or Babel route extractor
│   │
│   ├── core/                      # Steps 5 to 7: language-independent engine
│   │   ├── models.py              # Finding, Route, Issue (pydantic)
│   │   ├── normalize.py           # from_semgrep(), from_zap(), severity maps
│   │   ├── cwe.py                 # CWE extraction, fallback table, alias table
│   │   ├── routing.py             # find_route(method, url), find_route_for_code(file, line)
│   │   ├── correlate.py           # matching, scoring pairs, merge, dedupe, classify
│   │   ├── score.py               # risk score and sorting
│   │   └── fixes.py               # CWE template fixes + optional LLM layer
│   │
│   ├── storage/
│   │   ├── db.py                  # SQLite setup, save and load scans and issues
│   │   └── schema.sql
│   │
│   └── api/                       # Step 8: API
│       └── main.py                # FastAPI: /scans, /scans/{id}/issues, /issues/{id}
│
├── dashboard/                     # Step 8: UI
│   └── app.py                     # Streamlit: summary bar, sorted table, detail panel, export
│
├── data/
│   ├── raw/                       # saved semgrep.json, zap_alerts.json per scan
│   ├── sample/                    # pre-recorded results for the demo fallback
│   │   ├── flask_semgrep.json
│   │   ├── flask_zap.json
│   │   ├── juice_semgrep.json
│   │   └── juice_zap.json
│   └── scans.db                   # SQLite (git-ignored)
│
├── tests/
│   ├── test_normalize.py
│   ├── test_flask_adapter.py
│   ├── test_routing.py
│   ├── test_correlate.py          # the 5 or 6 hand-written match / no-match cases
│   └── test_score.py
│
├── scripts/
│   ├── run_scan.py                # CLI: python scripts/run_scan.py configs/flask_demo.yaml
│   ├── load_sample.py             # load data/sample/* so the demo works offline
│   └── evaluate.py                # compares output with GROUND_TRUTH.md, prints accuracy table
│
└── docs/
    ├── architecture.png           # diagram for the report
    ├── report.md                  # 3 to 4 page submission report
    └── demo_script.md             # 4 to 5 minute demo flow
```

## Planned Tech Stack

## Current API and evaluation

The current dashboard runs at [http://localhost:3000](http://localhost:3000)
after `docker compose up --build`. The FastAPI service exposes:

- `GET /api/graph?target_id=flask_demo`
- `GET /api/compliance?target_id=flask_demo`
- `GET /api/planner?target_id=flask_demo`
- `POST /api/patch` to generate a patch preview
- `POST /api/patch/apply` to apply the reviewed server-generated diff inside the selected target source tree
- `GET /api/export/sarif?target_id=flask_demo`; use `fail_on_confirmed_high=true` for a CI gate

Evaluate scanner reports against the selected target's manifest with:

```powershell
python scripts/evaluate.py --target flask_demo --semgrep data/sample/flask_demo_semgrep.json --zap data/sample/flask_demo_zap.json
```

The Juice Shop manifest covers the repository's checked-in offline sample
fixtures, not a complete vulnerability inventory. See [docs/BUILD.md](docs/BUILD.md)
and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
