from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

_PROFILE_ID = re.compile(r"^[A-Za-z0-9_-]+$")
_INTERNAL_HOSTS = {
    "localhost",
    "target-flask",
    "target-juice-shop",
}


@dataclass(frozen=True)
class RuntimeTargetProfile:
    target_id: str
    scheme: str
    netloc: str

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.netloc}"


def _config_dir() -> Path:
    configured = os.environ.get("MITIGATA_CONFIG_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[2] / "configs"


def load_target_profile(target_id: str) -> RuntimeTargetProfile:
    """Load a configured target by ID and reject non-local verification origins."""
    if not _PROFILE_ID.fullmatch(target_id):
        raise ValueError("Invalid target profile ID")

    config_dir = _config_dir()
    profile_path = (config_dir / f"{target_id}.yaml").resolve()
    if profile_path.parent != config_dir or not profile_path.is_file():
        raise ValueError(f"No target profile configured for {target_id!r}")

    with profile_path.open("r", encoding="utf-8") as handle:
        profile = yaml.safe_load(handle)
    if not isinstance(profile, dict) or profile.get("target_id") != target_id:
        raise ValueError(f"Target profile {target_id!r} is malformed")

    override_name = f"MITIGATA_TARGET_URL_{target_id.upper().replace('-', '_')}"
    raw_url = os.environ.get(override_name, profile.get("target_url"))
    if not isinstance(raw_url, str):
        raise ValueError(f"Target profile {target_id!r} has no target_url")
    parsed = urlsplit(raw_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"Target profile {target_id!r} has an invalid target_url")

    hostname = parsed.hostname.lower().rstrip(".")
    if hostname not in _INTERNAL_HOSTS:
        try:
            is_loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            raise ValueError(
                f"Target profile {target_id!r} must use a loopback or internal target host"
            )
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Target profile {target_id!r} has an invalid port") from exc

    netloc = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        netloc = f"{netloc}:{port}"
    return RuntimeTargetProfile(target_id, parsed.scheme, netloc)
