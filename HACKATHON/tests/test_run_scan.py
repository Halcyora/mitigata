from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import run_scan


def _flask_profile(source_dir: str) -> dict:
    return {
        "target_id": "flask_demo",
        "docker_service": "target-flask",
        "target_url": "http://target-flask:5050",
        "source_dir": source_dir,
        "semgrep_configs": ["p/python", "p/flask"],
        "exclude": ["node_modules"],
    }


def test_validate_target_rejects_non_local_or_mismatched_target():
    profile = _flask_profile("/targets/vulnerable_flask/source")
    assert run_scan.validate_target(profile) == (
        "target-flask",
        "http://target-flask:5050",
    )

    profile["target_url"] = "http://example.com"
    with pytest.raises(ValueError, match="configured internal service"):
        run_scan.validate_target(profile)


def test_run_semgrep_uses_container_and_persists_json_report(tmp_path, monkeypatch):
    root = tmp_path
    targets = root / "targets"
    source = targets / "vulnerable_flask" / "source"
    source.mkdir(parents=True)
    raw = root / "data" / "raw"
    monkeypatch.setattr(run_scan, "ROOT", root)
    monkeypatch.setattr(run_scan, "TARGETS_DIR", targets)
    monkeypatch.setattr(run_scan, "RAW_DIR", raw)

    def fake_run_compose(command):
        assert command[:5] == ["--profile", "scanners", "run", "--rm", "--no-deps"]
        assert "semgrep" in command
        assert "--config" in command
        assert "/targets/vulnerable_flask/source" in command
        temporary_report = raw / Path(command[command.index("--output") + 1]).name
        temporary_report.write_text(json.dumps({"results": [{"check_id": "test"}]}))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(run_scan, "run_compose", fake_run_compose)

    report = run_scan.run_semgrep(
        _flask_profile("/targets/vulnerable_flask/source")
    )

    assert report == {"results": [{"check_id": "test"}]}
    assert json.loads((raw / "flask_demo-semgrep.json").read_text()) == report


def test_run_dast_starts_only_profile_target_and_runs_zap(tmp_path, monkeypatch):
    root = tmp_path
    raw = root / "data" / "raw"
    monkeypatch.setattr(run_scan, "ROOT", root)
    monkeypatch.setattr(run_scan, "RAW_DIR", raw)
    calls = []

    def fake_run_compose(command):
        calls.append(command)
        if command[0] == "up":
            return subprocess.CompletedProcess(command, 0, "", "")
        assert command[:5] == ["--profile", "scanners", "run", "--rm", "--no-deps"]
        assert "zap" in command
        assert command[command.index("-t") + 1] == "http://target-flask:5050"
        temporary_report = raw / Path(command[command.index("-J") + 1]).name
        temporary_report.write_text(json.dumps({"site": [{"alerts": []}]}))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(run_scan, "run_compose", fake_run_compose)

    report = run_scan.run_dast(_flask_profile("/targets/vulnerable_flask/source"))

    assert calls[0] == ["up", "--detach", "--wait", "target-flask"]
    assert report == {"site": [{"alerts": []}]}
    assert (raw / "flask_demo-zap.json").is_file()


def test_count_zap_alerts_supports_standard_nested_report():
    assert run_scan.count_zap_alerts(
        {"site": [{"alerts": [{"pluginId": "100"}]}, {"alerts": []}]}
    ) == 1
