# Architecture

The engine reads a selected target profile, parses that target's Semgrep and ZAP JSON into `UnifiedFinding`, extracts route and code scopes through the language adapter, then correlates findings under target/CWE/route/scope/parameter gates. Classification labels and confidence remain deterministic.

The FastAPI service exposes the graph, compliance calculations, planner state, streaming verification, patch suggestions, and SARIF export. Patch generation tries the configured Sarvam model and validates its single-file diff before returning it; otherwise it uses a sink template. Patch suggestions are previews and are never applied by the API.

The React UI displays the correlation graph, merged evidence, business risk mappings, runtime re-test controls, patch previews, and planner/model status. GraphCodeBERT is ranking-only and cannot change deterministic decisions. Flask and Juice Shop data stay isolated by target ID.
