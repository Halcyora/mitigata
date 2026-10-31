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

Run `npm run build` to type-check and create the production bundle. The
container serves that bundle on port 3000 using Vite Preview.
