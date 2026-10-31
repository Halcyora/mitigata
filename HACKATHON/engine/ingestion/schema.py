from __future__ import annotations

from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class UnifiedFinding(BaseModel):
    """Common SAST/DAST finding schema for the build-plan pipeline."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    target_id: str
    source: Literal["sast", "dast"]
    cwe_id: str
    label: Literal["Confirmed", "Code only", "Runtime only"] | None = None

    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    function: str | None = None
    sink_type: str | None = None

    url: str | None = None
    method: str | None = None
    route: str | None = None
    parameter: str | None = None
    parameter_source: Literal["path", "query", "form", "json", "header"] | None = None
    evidence: str | None = None
    http_status: int | None = None

    rule_id: str | None = None
    severity: str = "MEDIUM"
    reachable: bool | None = None
    routes: list[str] = Field(default_factory=list)
    merged_from: list[str] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": "abc-123",
                "target_id": "flask_demo",
                "source": "sast",
                "cwe_id": "CWE-89",
                "label": "Confirmed",
                "file": "app/app.py",
                "line": 47,
                "severity": "HIGH",
                "sink_type": "sql_injection",
            }
        }
    }
