from __future__ import annotations

from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class UnifiedFinding(BaseModel):
    """Common SAST/DAST finding schema for the build-plan pipeline."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    target_id: str
    source: Literal["sast", "dast"]
    cwe_id: str
    label: Optional[Literal["Confirmed", "Code only", "Runtime only"]] = None
    file: Optional[str] = None
    line: Optional[int] = None
    function: Optional[str] = None
    sink_type: Optional[str] = None
    route: Optional[str] = None
    parameter: Optional[str] = None
    evidence: Optional[str] = None
