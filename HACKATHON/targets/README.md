# Target applications

The target source trees are upstream checkouts and are intentionally not copied
into this repository. Fetch the exact tested revisions before building:

```powershell
.\scripts\fetch_targets.ps1
.\scripts\fetch_flask_wheels.ps1
docker compose up --build
```

| Profile | Upstream repository | Revision | Container port |
|---|---|---|---:|
| `flask_demo` | [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | `b6a4f97afd466e83e1f60781494252dec1c37039` | 5050 |
| `juice_shop` | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | `f189f521266f42c6bd05884468292000cee852ed` (`v20.3.0`) | 3000 |

Both services are attached only to Docker's internal `targets` network. Their
ports are not published to the host. This keeps the intentionally vulnerable
applications isolated; later scanner/API services should join this network to
reach them. Do not expose these target containers to an untrusted network.

The Flask fixture's reference findings are tracked in
`targets/vulnerable_flask/GROUND_TRUTH.md` and
`data/ground_truth/flask_demo.yaml`. Those files define the expected route,
CWE, and suppressed dead-code behaviour used by the Phase 1 scoring model.

Juice Shop runs the official `v20.3.0` container image by immutable digest,
matching the pinned source tag used for static analysis. Flask dependencies
are downloaded as Linux/Python 3.11 wheels on the host and installed offline
during the image build, so TLS verification remains enabled throughout.

The Flask upstream is an old Python 2 application. Its source checkout remains
unchanged; the local Dockerfile uses a Python 3 runtime plus a small, checked
compatibility patch and pinned dependencies. The runtime patch is separate from
the upstream source and is listed by the `runtime_overlay` field in the Flask
profile. The test target is not a production deployment.
