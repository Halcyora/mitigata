from __future__ import annotations


def calculate_risk_score(confirmed_count: int, runtime_only_count: int = 0) -> int:
    """Simple placeholder risk score for demo and reporting hooks."""
    return confirmed_count * 10 + runtime_only_count * 3
