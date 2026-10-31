# Flask build inputs

This document records the exact build inputs for the Flask reference target used in Phase 1.7.

## Source revision

- Repository: `https://github.com/we45/Vulnerable-Flask-App.git`
- Pinned revision: `b6a4f97afd466e83e1f60781494252dec1c37039`

## Runtime overlay

- Local patch script: `targets/vulnerable_flask/patch_runtime.py`
- Runtime requirements: `targets/vulnerable_flask/requirements.txt`
- Offline wheelhouse: `targets/vulnerable_flask/wheelhouse/`

## Docker build contract

The Flask image is built from `targets/vulnerable_flask/Dockerfile` and installs:

1. the pinned Python dependencies from `requirements.txt`
2. the cached wheelhouse artifacts from `wheelhouse/`
3. the upstream app source from `source/app/`
4. the compatibility patch from `patch_runtime.py`

This ensures reproduction of the Phase 1 target without weakening TLS verification or drifting away from the pinned upstream revision.
