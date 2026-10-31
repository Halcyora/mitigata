"""Unified ingestion and normalization layer."""

from .incremental import CorrelationEvent, IncrementalCorrelator, correlate_incremental
from .schema import UnifiedFinding
from .semgrep_parser import normalize_finding_path, parse_semgrep_json
from .zap_parser import parse_zap_json

__all__ = [
    "UnifiedFinding",
    "CorrelationEvent",
    "IncrementalCorrelator",
    "correlate_incremental",
    "normalize_finding_path",
    "parse_semgrep_json",
    "parse_zap_json",
]
