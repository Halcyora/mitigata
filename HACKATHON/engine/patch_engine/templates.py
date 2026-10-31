from __future__ import annotations


def default_fix_template(cwe_id: str) -> str:
    """Return a deterministic fix hint used before LLM patching is enabled."""
    return f"Review the sink for CWE {cwe_id} and constrain user-controlled input before use."
