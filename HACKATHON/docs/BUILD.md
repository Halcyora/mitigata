# Build and evaluation

## Containers

Run `docker compose up --build` from this directory. Compose starts the API, UI, and isolated target services. Use `docker compose down` to stop the stack.

## Local evaluator

Run `python scripts/evaluate.py --target TARGET --semgrep SEMGREP_JSON --zap ZAP_JSON`. The evaluator compares normalized findings to `data/ground_truth/TARGET.yaml`, prints precision/recall and unmatched records, and exits nonzero if expected findings are missing. Keep evaluation target-specific. `juice_shop.yaml` currently describes the checked-in offline samples only.

## API behavior

- SARIF 2.1.0 export includes finding locations and correlation properties. `fail_on_confirmed_high=true` returns HTTP 409 when the target has a Confirmed HIGH or CRITICAL issue, allowing CI to fail.
- Compliance results include the four framework mappings when available and an INR exposure estimate per finding.
- Patch API accepts a target and finding ID, reads only that target's source tree, and returns a generated diff or deterministic snippet as a preview. A reviewed unified diff can be applied through `/api/patch/apply`; snippets stay preview-only.
