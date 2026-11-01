# Correlation graph dashboard

The Phase 7 dashboard is a React + Vite application. It fetches target-scoped
graph snapshots from the FastAPI engine, lays out the endpoint-to-finding path
with ELK, and streams runtime verification events into the graph and detail
panel.

## Run locally

```powershell
npm ci
npm run dev
```

The development server is available at `http://localhost:5173` and calls the
engine at `http://localhost:8000`. Set `VITE_API_BASE_URL` when the engine is
hosted elsewhere. The target selector keeps graph queries and verification
requests isolated by `target_id`.

The issue queue shows correlation status and a 0–100 severity/exploitability
priority score. Finding details expose scanner evidence records, merged alert
IDs, payloads, source context, and bounded verification history. The scan panel
compares the latest scan with the previous scan of the same type. SARIF export
is available beside a CI gate that returns HTTP 409 for confirmed High/Critical
findings.

Run `npm run build` to type-check and create the production bundle. The
container serves that bundle on port 3000 using Vite Preview.
