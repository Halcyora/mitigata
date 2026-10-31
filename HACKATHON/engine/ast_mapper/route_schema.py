from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


ParameterSource = Literal["path", "query", "form", "json", "header"]


class CodeScope(BaseModel):
    """Target-relative source span for a route handler or direct callee."""

    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    function: str

    @field_validator("file")
    @classmethod
    def require_target_relative_file(cls, value: str) -> str:
        normalized = value.replace("\\", "/")
        if (
            not normalized
            or normalized.startswith("/")
            or re.match(r"^[A-Za-z]:", normalized)
            or ".." in PurePosixPath(normalized).parts
        ):
            raise ValueError("Code scope file must be target-relative")
        return PurePosixPath(normalized).as_posix()

    @model_validator(mode="after")
    def require_ordered_lines(self) -> CodeScope:
        if self.end_line < self.start_line:
            raise ValueError("Code scope end_line must be >= start_line")
        return self


class ParameterRead(BaseModel):
    """A statically identified request input read by a route scope."""

    name: str
    source: ParameterSource


class RouteNode(BaseModel):
    """Normalized route metadata consumed by the ingestion correlator."""

    target_id: str
    raw_url: str
    normalized_url: str
    methods: list[str] = Field(default_factory=list)
    handler: str
    scopes: list[CodeScope] = Field(default_factory=list)
    input_parameters: list[ParameterRead] = Field(default_factory=list)
    resolved: bool = True
    unresolved_reasons: list[str] = Field(default_factory=list)

    def matches_path(self, path: str) -> bool:
        """Match a concrete URL path against this route's normalized template."""
        if not self.resolved:
            return False
        template_parts = self.normalized_url.strip("/").split("/")
        path_parts = path.strip("/").split("/")
        if len(template_parts) != len(path_parts):
            return False
        return all(
            template.startswith("{")
            and template.endswith("}")
            and bool(segment)
            or template == segment
            for template, segment in zip(template_parts, path_parts)
        )

    def matches_method(self, method: str | None) -> bool:
        """Require a known method before considering a runtime route match."""
        if method is None or not method.strip():
            return False
        normalized_methods = {candidate.upper() for candidate in self.methods}
        return method.strip().upper() in normalized_methods

    def contains_location(self, file: str | None, line: int | None) -> bool:
        """Check exact target-relative file and inclusive source-line scope."""
        if file is None or line is None:
            return False
        return any(
            scope.file == file and scope.start_line <= line <= scope.end_line
            for scope in self.scopes
        )

    def model_post_init(self, __context: object) -> None:
        if not self.resolved and not self.unresolved_reasons:
            self.unresolved_reasons.append("route resolution was incomplete")
