from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import yaml

from .schema import UnifiedFinding


CWE_MAP = {
    "python.lang.security.audit.dangerous-system-call": "CWE-78",
    "python.lang.security.audit.eval-detected": "CWE-95",
    "python.lang.security.deserialization.avoid-pickle": "CWE-502",
    "python.lang.security.audit.hardcoded-password": "CWE-798",
    "python.lang.security.audit.hardcoded-secret": "CWE-798",
    "python.flask.security.injection.tainted-string-from-http-params": "CWE-89",
    "python.flask.security.xss.audit.template-unescaped-extension": "CWE-79",
    "python.flask.security.audit.render-template-string": "CWE-94",
    "python.jwt.security.unverified-jwt-decode": "CWE-347",
    "python.jwt.security.jwt-hardcoded-secret": "CWE-347",
    "python.sqlalchemy.security.sqlalchemy-execute-injection": "CWE-89",
    "python.lang.security.audit.formatted-sql-query": "CWE-89",
    "python.lang.security.audit.use-of-md5": "CWE-916",
    "javascript.express.security.audit.express-sqli": "CWE-89",
    "javascript.lang.security.audit.detect-non-literal-regexp": "CWE-1333",
    "javascript.lang.security.audit.unsafe-dynamic-method": "CWE-749",
}

SINK_TYPE_MAP = {
    "CWE-89": "sql_injection",
    "CWE-78": "command_injection",
    "CWE-94": "ssti",
    "CWE-96": "ssti",
    "CWE-95": "eval_injection",
    "CWE-347": "jwt_weak_secret",
    "CWE-502": "insecure_deserialisation",
    "CWE-798": "hardcoded_secret",
    "CWE-916": "weak_hash",
    "CWE-79": "xss",
    "CWE-601": "open_redirect",
    "CWE-200": "information_disclosure",
    "CWE-327": "weak_crypto",
    "CWE-704": "unsafe_type_conversion",
}

_CWE_PATTERN = re.compile(r"CWE-\s*(\d+)", re.IGNORECASE)


def _profile_source_roots(target_id: str) -> list[Path]:
    config_dir = Path(__file__).resolve().parents[2] / "configs"
    if not config_dir.is_dir():
        return []

    for config_path in sorted(config_dir.glob("*.yaml")):
        with config_path.open("r", encoding="utf-8") as handle:
            profile = yaml.safe_load(handle) or {}
        if not isinstance(profile, dict):
            raise ValueError(f"Target profile must be a YAML object: {config_path}")
        if profile.get("target_id") != target_id or not profile.get("source_dir"):
            continue

        raw_source_dir = str(profile["source_dir"])
        source_dir = Path(raw_source_dir)
        if source_dir.is_absolute():
            try:
                target_relative = source_dir.relative_to(Path("/targets"))
            except ValueError:
                return [source_dir]
            return [
                Path("/targets") / target_relative,
                Path(__file__).resolve().parents[2] / "targets" / target_relative,
            ]
        return [(Path(__file__).resolve().parents[2] / source_dir).resolve()]
    return []


def normalize_finding_path(
    path: str, target_id: str, source_root: str | Path | None = None
) -> str:
    """Return a stable target-relative path without leaking host/container roots."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError("Semgrep finding path must be a non-empty string")

    normalized_input = path.strip().replace("\\", "/")
    windows_path = PureWindowsPath(path)
    is_absolute = (
        Path(normalized_input).is_absolute()
        or PurePosixPath(normalized_input).is_absolute()
        or windows_path.is_absolute()
    )

    if not is_absolute:
        relative = PurePosixPath(normalized_input)
        if ".." in relative.parts:
            raise ValueError(f"Semgrep finding path escapes the target source root: {path}")
        return relative.as_posix()

    roots = (
        [Path(source_root)]
        if source_root is not None
        else _profile_source_roots(target_id)
    )
    if roots:
        candidate = Path(path).resolve()
        for root in roots:
            try:
                return candidate.relative_to(root.resolve()).as_posix()
            except ValueError:
                pass
            candidate_posix = PurePosixPath(normalized_input)
            root_posix = PurePosixPath(root.as_posix())
            try:
                return candidate_posix.relative_to(root_posix).as_posix()
            except ValueError:
                pass

    raise ValueError(
        f"Cannot make absolute Semgrep path target-relative for target {target_id!r}: {path}"
    )


def _extract_cwe(metadata_cwe: Any, rule_id: str) -> str:
    values = metadata_cwe if isinstance(metadata_cwe, list) else [metadata_cwe]
    for value in values:
        if not isinstance(value, str):
            continue
        match = _CWE_PATTERN.search(value)
        if match:
            return f"CWE-{match.group(1)}"
        numeric = re.fullmatch(r"\s*(\d+)\s*", value)
        if numeric:
            return f"CWE-{numeric.group(1)}"
    return CWE_MAP.get(rule_id, "CWE-UNKNOWN")


def parse_semgrep_json(
    path: str | Path,
    target_id: str,
    *,
    source_root: str | Path | None = None,
) -> list[UnifiedFinding]:
    """Parse Semgrep JSON results into normalized SAST findings."""
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Semgrep JSON root must be an object")

    results = data.get("results", [])
    if not isinstance(results, list):
        raise ValueError("Semgrep JSON 'results' must be a list")

    findings: list[UnifiedFinding] = []
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ValueError(f"Semgrep result at index {index} must be an object")
        try:
            rule_id = result["check_id"]
            start = result["start"]
            result_path = result["path"]
            line = start["line"]
        except (KeyError, TypeError) as exc:
            raise ValueError(f"Semgrep result at index {index} is missing required fields") from exc
        if (
            not isinstance(rule_id, str)
            or not isinstance(start, dict)
            or not isinstance(result_path, str)
        ):
            raise ValueError(f"Semgrep result at index {index} has invalid rule/location data")

        extra = result.get("extra", {})
        if extra is None:
            extra = {}
        if not isinstance(extra, dict):
            raise ValueError(f"Semgrep result at index {index} has invalid 'extra' data")
        metadata = extra.get("metadata", {})
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise ValueError(f"Semgrep result at index {index} has invalid metadata")
        cwe_id = _extract_cwe(metadata.get("cwe"), rule_id)
        raw_severity = extra.get("severity") or metadata.get("severity") or "WARNING"
        severity = str(raw_severity).upper()
        normalized_path = normalize_finding_path(result_path, target_id, source_root)
        raw_lines = extra.get("lines") or ""
        raw_message = extra.get("message") or ""
        sast_evidence = str(raw_message)[:500] if raw_message else ""
        sast_snippet = str(raw_lines)[:1000] if raw_lines else ""

        findings.append(
            UnifiedFinding(
                target_id=target_id,
                source="sast",
                cwe_id=cwe_id,
                file=normalized_path,
                line=line,
                rule_id=rule_id,
                evidence_items=[{
                    "source": "SAST",
                    "rule_id": rule_id,
                    "file": normalized_path,
                    "line": line,
                    "severity": severity,
                    "evidence": sast_evidence,
                    "snippet": sast_snippet,
                }],
                severity=severity,
                sink_type=SINK_TYPE_MAP.get(cwe_id, "unknown"),
                label="Code only",
            )
        )
    return findings
