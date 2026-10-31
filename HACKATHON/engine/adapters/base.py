from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..ast_mapper.route_schema import RouteNode


@dataclass(frozen=True)
class TargetProfile:
    target_id: str
    language: str
    framework: str
    source_dir: Path


class RouteAdapter(Protocol):
    """Language adapter contract for the three deterministic mapping passes."""

    def discover_routes(self, profile: TargetProfile) -> list[RouteNode]: ...

    def add_one_hop_scopes(
        self, routes: list[RouteNode], profile: TargetProfile
    ) -> None: ...

    def extract_request_parameters(
        self, routes: list[RouteNode], profile: TargetProfile
    ) -> None: ...
