# Flask reference vulnerability map

This fixture is the controlled baseline for Objective 01 and Objective 02. It is intentionally scoped to the Flask target and should not be mixed with Juice Shop results in a single report.

## Route map from `app/app.py`

| Route | Handler | Vulnerability | CWE | Obj 01 type | Expected label |
|---|---|---|---|---|---|
| `POST /login` | `login()` | JWT signed with hardcoded `'secret'` | CWE-347 | Broken Auth | Confirmed |
| `POST /register/user` | `reg_customer()` | MD5 password hashing | CWE-916 | Weak Crypto | Confirmed |
| `POST /fetch/customer` | `fetch_customer()` | JWT decoded with `verify=False` | CWE-347 | Broken Auth | Confirmed |
| `GET /` | `sitemap()` | Exposes full route map | CWE-200 | Info Disclosure | Code only |
| `404 handler` | `pnf(e)` | SSTI via `request.url` in `render_template_string` | CWE-94 | SSTI | Code only → Confirmed after probe |
| `_legacy_*` functions | dead code helpers | SQLi, CMDi, pickle, eval, SSTI, XSS | CWE-89/78/502/95/94/79 | Multiple | Code only (suppressed) |
| Config | `SECRET_KEY_HMAC` | Hardcoded JWT secret | CWE-798 | Hardcoded Credentials | Runtime only |

## Operational notes

- The app listens on port `5050` (`APP_PORT = os.environ.get('APP_PORT', 5050)`).
- The 404 error handler is the key live verification path: a request to a missing route with `{{7*7}}` in the URL should return `49`, confirming the SSTI issue.
- The dead-code module is intentionally unreachable under the AST call graph. That ensures suppression of noisy SAST-only findings without compromising the route coverage signal.

## Dead-code suppression set

This local fixture includes a legacy helper module, `dead_code_helpers.py`, to model unreachable application code that SAST still reports. The functions are not imported by any active route and therefore remain `Code only` rather than `Confirmed`.

| Function | CWE | Purpose |
|---|---|---|
| `_legacy_export_users` | CWE-89 | raw SQL concat |
| `_legacy_run_report` | CWE-78 | command injection |
| `_legacy_deserialise_session` | CWE-502 | unsafe pickle |
| `_legacy_eval_formula` | CWE-95 | eval injection |
| `_legacy_template_render` | CWE-94 | SSTI |
| `_legacy_sql_report` | CWE-89 | f-string SQL |
| `_legacy_render_xss` | CWE-79 | reflected XSS |
| `_legacy_path_read` | CWE-22 | path traversal |
| `_legacy_redirect` | CWE-601 | open redirect |

This yields a suppression set large enough to demonstrate the required filtering behaviour without mixing it with the real runtime findings.
