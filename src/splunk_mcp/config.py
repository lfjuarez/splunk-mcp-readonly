"""Settings loaded from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

HARD_MAX_ROWS = 1000


class ConfigError(ValueError):
    """Raised when the environment does not describe a usable configuration."""


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, value: str | None, default: int) -> int:
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {value!r}") from None


@dataclass(frozen=True)
class Settings:
    url: str
    token: str | None = field(default=None, repr=False)
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    verify_tls: bool = True
    default_earliest: str = "-24h"
    max_rows: int = 200
    timeout_s: int = 60
    allowed_indexes: list[str] | None = None
    audit_log: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        url = (env.get("SPLUNK_URL") or "").strip().rstrip("/")
        token = (env.get("SPLUNK_TOKEN") or "").strip() or None
        username = (env.get("SPLUNK_USERNAME") or "").strip() or None
        password = env.get("SPLUNK_PASSWORD") or None

        missing: list[str] = []
        if not url:
            missing.append("SPLUNK_URL")
        if not token and not (username and password):
            missing.append("SPLUNK_TOKEN (or SPLUNK_USERNAME and SPLUNK_PASSWORD)")
        if missing:
            raise ConfigError("missing environment variables: " + ", ".join(missing))

        max_rows = _int("SPLUNK_MAX_ROWS", env.get("SPLUNK_MAX_ROWS"), 200)
        max_rows = max(1, min(max_rows, HARD_MAX_ROWS))
        raw_indexes = env.get("SPLUNK_ALLOWED_INDEXES") or ""
        indexes = [i.strip() for i in raw_indexes.split(",") if i.strip()]

        return cls(
            url=url,
            token=token,
            username=username,
            password=password,
            verify_tls=_bool(env.get("SPLUNK_VERIFY_TLS"), True),
            default_earliest=(env.get("SPLUNK_DEFAULT_EARLIEST") or "-24h").strip(),
            max_rows=max_rows,
            timeout_s=_int("SPLUNK_TIMEOUT_S", env.get("SPLUNK_TIMEOUT_S"), 60),
            allowed_indexes=indexes or None,
            audit_log=(env.get("SPLUNK_MCP_AUDIT_LOG") or "").strip() or None,
        )
