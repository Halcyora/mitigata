from __future__ import annotations

import logging
import sys
from types import ModuleType, SimpleNamespace

import pytest

from engine.patch_engine.llm_patcher import (
    PatchGenerationError,
    generate_llm_patch,
    generate_patch,
    validate_unified_diff,
)
from engine.patch_engine.templates import (
    PATCH_TEMPLATES,
    default_fix_template,
    get_template_patch,
)

_VALID_DIFF = """\
--- a/app/routes.py
+++ b/app/routes.py
@@ -10,1 +10,1 @@
-query = "SELECT * FROM users WHERE name='" + name + "'"
+query = "SELECT * FROM users WHERE name = ?"
"""


def _install_fake_openai(monkeypatch, responses):
    class OpenAIError(Exception):
        pass

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.chat = SimpleNamespace(
                completions=SimpleNamespace(create=self._create)
            )

        def close(self):
            return None

        def _create(self, **kwargs):
            responses["requests"].append((self.kwargs, kwargs))
            result = responses["results"].pop(0)
            if isinstance(result, Exception):
                raise result
            return result

    fake_openai = ModuleType("openai")
    fake_openai.OpenAI = FakeOpenAI
    fake_openai.OpenAIError = OpenAIError
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    return OpenAIError


def _response(content: str):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
    )


def test_templates_cover_supported_sinks_and_cwe_aliases():
    assert set(PATCH_TEMPLATES) == {
        "sql_injection",
        "xss",
        "command_injection",
        "weak_hash",
        "jwt_weak_secret",
        "ssti",
    }
    assert get_template_patch("sql_injection") == PATCH_TEMPLATES["sql_injection"]
    assert get_template_patch("unknown") is None
    assert default_fix_template("CWE-89") == PATCH_TEMPLATES["sql_injection"]
    assert "safe API" in default_fix_template("CWE-999")
    assert "subprocess.run" in PATCH_TEMPLATES["command_injection"]
    assert "shlex.quote" not in PATCH_TEMPLATES["command_injection"]
    assert "render_template_string" not in PATCH_TEMPLATES["ssti"]


def test_unified_diff_validator_accepts_only_expected_single_file_diff():
    validated = validate_unified_diff(_VALID_DIFF, "app/routes.py")
    assert validated == _VALID_DIFF

    git_style = (
        "diff --git a/app/routes.py b/app/routes.py\n"
        "index 1111111..2222222 100644\n"
        + _VALID_DIFF
    )
    assert validate_unified_diff(git_style, "app/routes.py") == git_style


@pytest.mark.parametrize(
    "patch",
    [
        "```diff\n" + _VALID_DIFF + "```",
        _VALID_DIFF.replace("app/routes.py", "other.py"),
        _VALID_DIFF + "\n--- a/other.py\n+++ b/other.py\n",
        _VALID_DIFF.replace("@@ -10,1 +10,1 @@", "@@ malformed @@"),
        _VALID_DIFF.replace("+query = ", "+query = x\n+extra = "),
        "--- a/app/routes.py\n+++ b/app/routes.py\n@@ -10,1 +10,1 @@\n",
        "diff --git a/other.py b/other.py\n" + _VALID_DIFF,
    ],
)
def test_unified_diff_validator_rejects_malformed_or_out_of_scope_patch(patch):
    assert validate_unified_diff(patch, "app/routes.py") is None


@pytest.mark.parametrize("file_path", ["../secrets.py", "/etc/passwd", "C:\\secrets.py"])
def test_patch_input_rejects_absolute_or_traversal_paths(file_path):
    with pytest.raises(PatchGenerationError, match="relative path"):
        generate_llm_patch("sql_injection", file_path, 1, "code")


def test_patch_input_rejects_invalid_line_and_oversized_context():
    with pytest.raises(PatchGenerationError, match="positive integer"):
        generate_llm_patch("sql_injection", "app/routes.py", 0, "code")
    with pytest.raises(PatchGenerationError, match="exceeds"):
        generate_llm_patch(
            "sql_injection",
            "app/routes.py",
            1,
            "x" * 16_001,
        )


def test_llm_patcher_uses_sarvam_model_and_validates_result(monkeypatch):
    monkeypatch.setenv("SARVAM_API_KEY", "test-key")
    monkeypatch.setenv("SARVAM_BASE_URL", "https://api.sarvam.ai/v2")
    monkeypatch.setenv("SARVAM_MODEL", "glm5.3")
    responses = {
        "requests": [],
        "results": [_response(_VALID_DIFF)],
    }
    _install_fake_openai(monkeypatch, responses)

    result = generate_patch("sql_injection", "app/routes.py", 10, "source")

    assert result.content == _VALID_DIFF
    assert result.kind == "unified_diff"
    assert result.source == "sarvam"
    assert result.model == "glm5.3"
    assert responses["requests"][0][0]["base_url"] == "https://api.sarvam.ai/v2"
    assert responses["requests"][0][1]["model"] == "glm5.3"
    assert responses["requests"][0][1]["reasoning_effort"] == "low"
    assert responses["requests"][0][0]["timeout"] == 10.0
    assert responses["requests"][0][0]["max_retries"] == 0
    prompt = responses["requests"][0][1]["messages"][1]["content"]
    assert "untrusted data" in prompt
    assert "<source_context>\nsource\n</source_context>" in prompt


def test_unexpected_sdk_errors_are_not_silently_swallowed(monkeypatch, caplog):
    monkeypatch.setenv("SARVAM_API_KEY", "test-key")
    responses = {
        "requests": [],
        "results": [
            RuntimeError("unexpected failure"),
        ],
    }
    _install_fake_openai(monkeypatch, responses)

    class FakeOpenAIError(Exception):
        pass

    module = sys.modules["openai"]
    module.OpenAIError = FakeOpenAIError

    with pytest.raises(RuntimeError, match="unexpected failure"):
        generate_patch("sql_injection", "app/routes.py", 10, "source")

    assert "unexpected failure" not in caplog.text


def test_configured_api_errors_log_and_fall_back(monkeypatch, caplog):
    monkeypatch.setenv("SARVAM_API_KEY", "test-key")
    responses = {
        "requests": [],
        "results": [],
    }
    api_error = _install_fake_openai(monkeypatch, responses)
    responses["results"].append(api_error("Sarvam unavailable"))
    with caplog.at_level(logging.WARNING):
        result = generate_patch("sql_injection", "app/routes.py", 10, "source")

    assert result.kind == "template"
    assert result.source == "deterministic_template"
    assert "Sarvam unavailable" in caplog.text
    assert len(responses["requests"]) == 1


def test_missing_configuration_uses_template_without_openai(monkeypatch):
    monkeypatch.delenv("SARVAM_API_KEY", raising=False)

    result = generate_patch("ssti", "app/templates.py", 20, "unsafe context")

    assert result.kind == "template"
    assert "render_template" in result.content


def test_unknown_sink_without_llm_patch_is_an_explicit_error(monkeypatch):
    monkeypatch.delenv("SARVAM_API_KEY", raising=False)

    with pytest.raises(PatchGenerationError, match="no template exists"):
        generate_patch("unknown_sink", "app/routes.py", 1, "source")
