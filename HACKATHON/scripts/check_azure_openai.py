"""Check Azure OpenAI credentials with a minimal chat completion.

Run from any directory with: python scripts/check_azure_openai.py
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

    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").strip()
    key = os.environ.get("AZURE_OPENAI_KEY", "").strip()
    deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "").strip()
    missing = [
        name
        for name, value in (
            ("AZURE_OPENAI_ENDPOINT", endpoint),
            ("AZURE_OPENAI_KEY", key),
            ("AZURE_OPENAI_DEPLOYMENT", deployment),
        )
        if not value
    ]
    if missing:
        print("Missing required setting(s): " + ", ".join(missing), file=sys.stderr)
        return 2

    try:
        from openai import APIConnectionError, AzureOpenAI, OpenAIError
    except ImportError:
        print(
            "The openai package is not installed. Install project requirements first.",
            file=sys.stderr,
        )
        return 2

    try:
        with AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=key,
            api_version="2024-02-01",
            timeout=15.0,
            max_retries=0,
        ) as client:
            client.chat.completions.create(
                model=deployment,
                messages=[{"role": "user", "content": "Reply with OK."}],
                max_tokens=5,
                temperature=0,
            )
    except OpenAIError as exc:
        status_code = getattr(exc, "status_code", None)
        if status_code == 401:
            print("Check failed: Azure rejected the key (HTTP 401).", file=sys.stderr)
        elif status_code == 403:
            print(
                "Check failed: Azure denied access (HTTP 403); check resource permissions.",
                file=sys.stderr,
            )
        elif status_code == 404:
            print(
                "Check failed: resource or deployment not found (HTTP 404); "
                "check the endpoint and deployment name.",
                file=sys.stderr,
            )
        elif status_code == 429:
            print(
                "Azure accepted the request but throttled it (HTTP 429); "
                "check quota and retry later.",
                file=sys.stderr,
            )
        else:
            if isinstance(exc, APIConnectionError):
                print(
                    "Check failed: could not reach Azure OpenAI; check the endpoint, "
                    "DNS, and network connection.",
                    file=sys.stderr,
                )
            else:
                print(
                    f"Check failed: Azure OpenAI request error ({type(exc).__name__}).",
                    file=sys.stderr,
                )
        return 1

    print(f"Check passed: Azure OpenAI responded using deployment '{deployment}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
