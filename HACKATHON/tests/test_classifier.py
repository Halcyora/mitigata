from __future__ import annotations

import pytest

from engine.classifier.classifier import (
    ClassificationError,
    ClassificationResult,
    Label,
    apply_classification,
    classify,
    sort_findings,
)
from engine.ingestion.schema import UnifiedFinding


@pytest.mark.parametrize(
    ("reachable", "verification", "config_only", "dual_confirmed", "label", "score"),
    [
        (None, "Confirmed", False, True, Label.CONFIRMED, 0.98),
        (False, "Confirmed", False, False, Label.CONFIRMED, 0.90),
        (True, "Confirmed", True, False, Label.CONFIRMED, 0.90),
        (False, "UNVERIFIED", True, False, Label.RUNTIME_ONLY, 0.85),
        (False, None, False, False, Label.CODE_ONLY, 0.95),
        (True, "Code only", False, False, Label.CODE_ONLY, 0.70),
        (None, "UNVERIFIED", False, False, Label.CODE_ONLY, 0.50),
    ],
)
def test_classification_priority_and_confidence(
    reachable, verification, config_only, dual_confirmed, label, score
):
    result = classify(
        ast_reachable=reachable,
        verification_label=verification,
        is_config_only=config_only,
        dual_confirmed=dual_confirmed,
    )

    assert isinstance(result, ClassificationResult)
    assert result.label is label
    assert result.confidence == score
    assert result.reason


def test_code_only_precedes_runtime_only_and_unknown_verification_is_conservative():
    assert classify(False, "Code only", True).label is Label.RUNTIME_ONLY
    assert classify(None, None, False).label is Label.CODE_ONLY
    assert classify(None, "UNVERIFIED", False).label is Label.CODE_ONLY
    assert classify(None, "Runtime only", False).label is Label.CODE_ONLY


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"ast_reachable": 1}, "ast_reachable"),
        ({"verification_label": "confirmed"}, "Unsupported verification label"),
        ({"is_config_only": "yes"}, "is_config_only"),
        ({"dual_confirmed": 1}, "dual_confirmed"),
    ],
)
def test_invalid_classification_inputs_are_rejected(kwargs, message):
    values = {
        "ast_reachable": None,
        "verification_label": None,
        "is_config_only": False,
        "dual_confirmed": False,
    }
    values.update(kwargs)
    with pytest.raises(ClassificationError, match=message):
        classify(**values)


def test_apply_classification_returns_copy_and_preserves_finding_evidence():
    finding = UnifiedFinding(
        id="finding-1",
        target_id="flask_demo",
        source="sast",
        cwe_id="CWE-89",
        label="Code only",
        reachable=True,
        evidence="existing evidence",
    )

    classified = apply_classification(
        finding,
        verification_label="Confirmed",
        dual_confirmed=True,
    )

    assert classified is not finding
    assert classified.label == "Confirmed"
    assert classified.confidence == 0.98
    assert classified.evidence == "existing evidence"
    assert finding.label == "Code only"
    assert finding.confidence is None


def test_confirmed_is_sorted_before_code_and_runtime_only_findings():
    findings = [
        UnifiedFinding(
            id="code",
            target_id="flask_demo",
            source="sast",
            cwe_id="CWE-89",
            label="Code only",
        ),
        UnifiedFinding(
            id="confirmed",
            target_id="flask_demo",
            source="sast",
            cwe_id="CWE-89",
            label="Confirmed",
        ),
        UnifiedFinding(
            id="runtime",
            target_id="flask_demo",
            source="dast",
            cwe_id="CWE-16",
            label="Runtime only",
        ),
    ]

    assert [finding.id for finding in sort_findings(findings)] == [
        "confirmed",
        "code",
        "runtime",
    ]
