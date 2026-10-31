from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="Mitigata correlation engine")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/targets")
def list_targets() -> list[str]:
    return ["flask_demo", "juice_shop"]
