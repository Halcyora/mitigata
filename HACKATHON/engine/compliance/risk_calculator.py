from __future__ import annotations

from typing import Any

CVSS_TO_PROBABILITY = {
    "CRITICAL": 0.85,
    "HIGH": 0.65,
    "MEDIUM": 0.40,
    "LOW": 0.15,
    "INFO": 0.05,
}

COST_PER_RECORD_INR = 5_000
CYBER_INSURANCE_THRESHOLD_INR = 5_000_000

INC06_REFERENCE = {
    "incident": "2017 Credit Bureau Breach",
    "records_exposed": 145_000_000,
    "estimated_exposure_inr": 145_000_000 * 5_000 * 0.85,
}


def _coerce_record_count(records_at_risk: Any) -> int:
    if isinstance(records_at_risk, bool):
        raise ValueError("records_at_risk must be a non-negative integer")
    if isinstance(records_at_risk, (int, float)):
        value = float(records_at_risk)
    elif isinstance(records_at_risk, str):
        try:
            value = float(records_at_risk)
        except ValueError as exc:  # pragma: no cover - defensive validation
            raise ValueError("records_at_risk must be numeric") from exc
    else:
        raise TypeError("records_at_risk must be numeric")

    if value < 0:
        raise ValueError("records_at_risk must be non-negative")
    return int(value)


def _severity_to_probability(severity: Any) -> float:
    if isinstance(severity, str):
        normalized = severity.strip().upper()
        if normalized in CVSS_TO_PROBABILITY:
            return CVSS_TO_PROBABILITY[normalized]
        if normalized.startswith("CWE-"):
            return 0.40
    if severity is None:
        return 0.40
    if hasattr(severity, "severity"):
        return _severity_to_probability(getattr(severity, "severity"))
    if isinstance(severity, (int, float)):
        return 0.40
    return 0.40


def calculate_risk_score(confirmed_count: int, runtime_only_count: int = 0) -> int:
    """Simple risk score used by the demo and reporting hooks."""
    return confirmed_count * 10 + runtime_only_count * 3


def calculate_inr_exposure(finding: Any, records_at_risk: int = 10_000) -> dict[str, Any]:
    """Estimate financial exposure from a severity and record count."""
    if isinstance(finding, dict):
        severity = finding.get("severity")
    else:
        severity = getattr(finding, "severity", None)

    probability = _severity_to_probability(severity)
    risk_count = _coerce_record_count(records_at_risk)
    exposure = risk_count * COST_PER_RECORD_INR * probability

    return {
        "breach_probability_pct": int(probability * 100),
        "records_at_risk": risk_count,
        "cost_per_record_inr": COST_PER_RECORD_INR,
        "total_exposure_inr": int(exposure),
        "total_exposure_formatted": f"₹{int(exposure):,}",
        "cyber_insurance_impact": exposure > CYBER_INSURANCE_THRESHOLD_INR,
        "ibm_benchmark_source": "IBM Cost of a Data Breach 2024 — India",
        "inc06_reference": INC06_REFERENCE,
    }
