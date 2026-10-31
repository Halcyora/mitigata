"""Check Sarvam API credentials with a minimal chat completion.

Run from any directory with: python scripts/check_sarvam.py
Optionally pass another environment file with --env-file.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def load_env_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Environment file not found: {path}")

    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, separator, value = line.partition("=")
        if not separator:
            continue
        name = name.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        if name:
            os.environ.setdefault(name, value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_env_file = Path(__file__).resolve().parents[1] / ".env"
    parser.add_argument(
        "--env-file",
        type=Path,
        default=default_env_file,
        help=f"Environment file to load (default: {default_env_file})",
    )
    args = parser.parse_args()

    try:
        load_env_file(args.env_file)
    except OSError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    base_url = os.environ.get("SARVAM_BASE_URL", "https://api.sarvam.ai/v2").strip()
    key = os.environ.get("SARVAM_API_KEY", "").strip()
    model = os.environ.get("SARVAM_MODEL", "glm5.3").strip()
    missing = [
        name
        for name, value in (
            ("SARVAM_BASE_URL", base_url),
            ("SARVAM_API_KEY", key),
            ("SARVAM_MODEL", model),
        )
        if not value
    ]
    if missing:
        print("Missing required setting(s): " + ", ".join(missing), file=sys.stderr)
        return 2

    try:
        from openai import APIConnectionError, OpenAI, OpenAIError
    except ImportError:
        print(
            "The openai package is not installed. Install project requirements first.",
            file=sys.stderr,
        )
        return 2

    try:
        with OpenAI(
            base_url=base_url,
            api_key=key,
            timeout=15.0,
            max_retries=0,
        ) as client:
            client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Reply with OK."}],
                max_tokens=32,
                temperature=0,
                reasoning_effort="low",
            )
    except OpenAIError as exc:
        status_code = getattr(exc, "status_code", None)
        if status_code == 401:
            print("Check failed: Sarvam rejected the key (HTTP 401).", file=sys.stderr)
        elif status_code == 403:
            print(
                "Check failed: Sarvam denied access (HTTP 403); check API access.",
                file=sys.stderr,
            )
        elif status_code == 404:
            print(
                "Check failed: model or API route not found (HTTP 404); "
                "check the base URL and model name.",
                file=sys.stderr,
            )
        elif status_code == 429:
            print(
                "Sarvam accepted the request but throttled it (HTTP 429); "
                "check quota and retry later.",
                file=sys.stderr,
            )
        else:
            if isinstance(exc, APIConnectionError):
                print(
                    "Check failed: could not reach Sarvam; check the base URL, "
                    "DNS, and network connection.",
                    file=sys.stderr,
                )
            else:
                print(
                    f"Check failed: Sarvam request error ({type(exc).__name__}).",
                    file=sys.stderr,
                )
        return 1

    print(f"Check passed: Sarvam responded using model '{model}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
