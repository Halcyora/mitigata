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
        "language": "python",
        "framework": "flask",
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
        assert command[command.index("semgrep") + 1] == "scan"
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


def test_run_semgrep_mounts_optional_trusted_ca(tmp_path, monkeypatch):
    root = tmp_path
    targets = root / "targets"
    source = targets / "vulnerable_flask" / "source"
    source.mkdir(parents=True)
    ca_path = root / "corporate-ca.crt"
    ca_path.write_text("test certificate", encoding="utf-8")
    raw = root / "data" / "raw"
    monkeypatch.setattr(run_scan, "ROOT", root)
    monkeypatch.setattr(run_scan, "TARGETS_DIR", targets)
    monkeypatch.setattr(run_scan, "RAW_DIR", raw)
    monkeypatch.setenv("MITIGATA_CA_CERT_PATH", str(ca_path))

    def fake_run_compose(command):
        volume_index = command.index("--volume")
        assert command[volume_index + 1] == (
            f"{ca_path.as_posix()}:/run/secrets/mitigata-ca.crt:ro"
        )
        env_index = command.index("--env")
        assert command[env_index + 1] == (
            "REQUESTS_CA_BUNDLE=/run/secrets/mitigata-ca.crt"
        )
        temporary_report = raw / Path(command[command.index("--output") + 1]).name
        temporary_report.write_text(json.dumps({"results": []}))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(run_scan, "run_compose", fake_run_compose)

    assert run_scan.run_semgrep(
        _flask_profile("/targets/vulnerable_flask/source")
    ) == {"results": []}


def test_run_semgrep_rejects_missing_optional_ca(tmp_path, monkeypatch):
    targets = tmp_path / "targets"
    source = targets / "vulnerable_flask" / "source"
    source.mkdir(parents=True)
    monkeypatch.setattr(run_scan, "TARGETS_DIR", targets)
    monkeypatch.setenv("MITIGATA_CA_CERT_PATH", str(tmp_path / "missing.crt"))

    with pytest.raises(FileNotFoundError, match="MITIGATA_CA_CERT_PATH"):
        run_scan.run_semgrep(
            _flask_profile("/targets/vulnerable_flask/source")
        )


def test_run_dast_starts_only_profile_target_and_runs_zap(tmp_path, monkeypatch):
    root = tmp_path
    targets = root / "targets"
    source = targets / "vulnerable_flask" / "source"
    source.mkdir(parents=True)
    (source / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.get('/hello')\n"
        "def hello(): return 'hello'\n",
        encoding="utf-8",
    )
    raw = root / "data" / "raw"
    monkeypatch.setattr(run_scan, "ROOT", root)
    monkeypatch.setattr(run_scan, "RAW_DIR", raw)
    monkeypatch.setattr(run_scan, "TARGETS_DIR", targets)
    calls = []

    def fake_run_compose(command):
        calls.append(command)
        if command[0] == "up":
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError("ZAP daemon startup is delegated to run_zap_plan")

    monkeypatch.setattr(run_scan, "run_compose", fake_run_compose)
    (raw).mkdir(parents=True)
    (raw / "flask_demo-semgrep.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "custom.sql-injection",
                        "path": "app.py",
                        "start": {"line": 4},
                        "extra": {
                            "severity": "ERROR",
                            "metadata": {"cwe": ["CWE-89"]},
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    expected_report = {
        "alerts": [],
        "tasks": [],
        "coverage": {"targeted_completed": 0, "broad_completed": 1},
        "scan_status": "COMPLETED",
    }

    def fake_run_zap_plan(plan):
        assert plan.target_id == "flask_demo"
        assert plan.target_url == "http://target-flask:5050"
        assert [task.raw_url for task in plan.broad_tasks] == ["/hello"]
        assert len(plan.targeted_tasks) == 1
        assert plan.targeted_tasks[0].finding_ids
        assert plan.targeted_tasks[0].zap_rule_ids == ["40018"]
        return expected_report

    monkeypatch.setattr(run_scan, "run_zap_plan", fake_run_zap_plan)

    report = run_scan.run_dast(_flask_profile("/targets/vulnerable_flask/source"))

    assert calls[0] == ["up", "--detach", "--wait", "target-flask"]
    assert report == expected_report


def test_count_zap_alerts_supports_standard_nested_report():
    assert run_scan.count_zap_alerts(
        {"site": [{"alerts": [{"pluginId": "100"}]}, {"alerts": []}]}
    ) == 1
