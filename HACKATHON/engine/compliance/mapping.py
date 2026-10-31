from __future__ import annotations

from typing import Any

COMPLIANCE_MAP: dict[str, dict[str, str]] = {
    "CWE-89": {
        "rbi_csf": "Annex I §4.2 — Baseline Controls: Input Validation & Parameterised Queries",
        "sebi_cscrf": "Domain 5: Application Security — Input Validation Controls",
        "iso_27001": "A.8.28 — Secure coding; A.8.25 — Secure development lifecycle",
        "dpdp_2023": "§8(1) — Data fiduciary must implement reasonable security safeguards",
    },
    "CWE-79": {
        "rbi_csf": "Annex I §4.2 — Baseline Controls: Output Encoding",
        "sebi_cscrf": "Domain 5: Application Security — Input Validation Controls",
        "iso_27001": "A.8.28 — Secure coding",
        "dpdp_2023": "§8(1) — Reasonable security safeguards",
    },
    "CWE-78": {
        "rbi_csf": "Annex I §4.2 — Baseline Controls: OS Command Injection Prevention",
        "sebi_cscrf": "Domain 5: Application Security — Secure Coding Standards",
        "iso_27001": "A.8.28 — Secure coding",
        "dpdp_2023": "§8(1) — Reasonable security safeguards for personal data processing",
    },
    "CWE-94": {
        "rbi_csf": "Annex I §4.2 — Baseline Controls: Template Injection Prevention",
        "sebi_cscrf": "Domain 5: Application Security — Secure Coding Standards",
        "iso_27001": "A.8.28 — Secure coding; A.8.29 — Security testing in development",
        "dpdp_2023": "§8(1) — Reasonable security safeguards",
    },
    "CWE-347": {
        "rbi_csf": "Annex I §4.3 — Identity & Access Management: Token Validation",
        "sebi_cscrf": "Domain 3: Identity & Access Management — Authentication Controls",
        "iso_27001": "A.8.5 — Secure authentication; A.8.3 — Information access restriction",
        "dpdp_2023": "§8(2) — Obligation to protect personal data from unauthorised access",
    },
    "CWE-502": {
        "rbi_csf": "Annex I §4.2 — Baseline Controls: Deserialisation Security",
        "sebi_cscrf": "Domain 5: Application Security — Secure Coding Standards",
        "iso_27001": "A.8.28 — Secure coding",
        "dpdp_2023": "§8(1) — Reasonable security safeguards",
    },
    "CWE-798": {
        "rbi_csf": "Annex I §4.3 — Identity & Access Management: Secrets Management",
        "sebi_cscrf": "Domain 3: IAM — Credential Management",
        "iso_27001": "A.5.17 — Authentication information",
        "dpdp_2023": "§8(2) — Obligation to protect personal data from unauthorised access",
    },
    "CWE-916": {
        "rbi_csf": "Annex I §4.3 — Identity & Access Management: Password Storage",
        "sebi_cscrf": "Domain 3: IAM — Password Management",
        "iso_27001": "A.5.17 — Authentication information; A.8.28 — Secure coding",
        "dpdp_2023": "§8(1) — Reasonable security safeguards for personal data (passwords)",
    },
}

FRAMEWORK_ORDER = ("rbi_csf", "sebi_cscrf", "iso_27001", "dpdp_2023")


def _normalise_cwe(cwe_id: Any) -> str | None:
    if cwe_id is None:
        return None
    if isinstance(cwe_id, dict):
        cwe_id = cwe_id.get("cwe_id") or cwe_id.get("cwe")
    elif hasattr(cwe_id, "cwe_id"):
        cwe_id = cwe_id.cwe_id
    elif hasattr(cwe_id, "cwe"):
        cwe_id = cwe_id.cwe

    if cwe_id is None:
        return None

    normalized = str(cwe_id).strip().upper()
    if not normalized:
        return None
    if not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized.lstrip('-')}"
    return normalized


def get_compliance_mapping(cwe_id: Any) -> dict[str, str] | None:
    """Return the specified compliance mapping for a CWE identifier."""
    normalized = _normalise_cwe(cwe_id)
    if normalized is None:
        return None
    return COMPLIANCE_MAP.get(normalized)


def map_finding_to_frameworks(finding: Any) -> dict[str, str] | None:
    """Resolve a compliant control map from a UnifiedFinding-like object or dict."""
    if isinstance(finding, dict):
        return get_compliance_mapping(finding.get("cwe_id") or finding.get("cwe"))
    if hasattr(finding, "cwe_id"):
        return get_compliance_mapping(finding.cwe_id)
    if hasattr(finding, "cwe"):
        return get_compliance_mapping(finding.cwe)
    return None


def map_cwe_to_frameworks(cwe_id: Any) -> dict[str, str] | None:
    """Backward-compatible alias for the direct CWE mapping lookup."""
    return get_compliance_mapping(cwe_id)


def frameworks_for_cwe(cwe_id: Any) -> dict[str, str] | None:
    """Alias for compliance mapping resolution."""
    return get_compliance_mapping(cwe_id)


__all__ = [
    "COMPLIANCE_MAP",
    "FRAMEWORK_ORDER",
    "map_finding_to_frameworks",
    "map_cwe_to_frameworks",
    "frameworks_for_cwe",
    "get_compliance_mapping",
]
