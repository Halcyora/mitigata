# SAST-DAST Correlator

## Current phase: target applications and Docker

The current codebase contains Python and JavaScript route parsers. Phase 1 adds
pinned upstream targets, per-target profiles, and a Docker Compose network that
keeps intentionally vulnerable apps isolated from host access.

From this directory, in PowerShell:

```powershell
.\scripts\fetch_targets.ps1
.\scripts\fetch_flask_wheels.ps1
docker compose up --build
```

Compose builds and starts the Flask reference app and OWASP Juice Shop. Neither
target publishes a port to the host. Later scanner/API services will join their
internal Docker network. Do not expose these target containers to untrusted
networks.

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
