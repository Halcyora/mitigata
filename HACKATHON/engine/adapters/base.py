from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterable


class RouteAdapter(ABC):
    """Base interface for source-to-route extraction adapters."""

    target_id: str
    language: str
    framework: str

    @abstractmethod
    def discover_routes(self, source_dir: str) -> Iterable[dict[str, Any]]:
        """Return normalized route definitions for the target source tree."""
        raise NotImplementedError

    @abstractmethod
    def discover_scopes(self, source_dir: str) -> Iterable[dict[str, Any]]:
        """Return code scopes and request-read metadata for the target."""
        raise NotImplementedError
