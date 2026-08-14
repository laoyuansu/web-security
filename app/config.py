"""Application configuration with fail-closed local security defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Runtime settings. Secrets are read from the process environment only."""

    host: str
    port: int
    admin_username: str
    admin_password: str
    session_secret: str
    database_path: Path


def _required_environment_value(name: str, minimum_length: int) -> str:
    value = os.getenv(name, "")
    if len(value) < minimum_length:
        raise RuntimeError(
            f"{name} must be set in the process environment and contain at least "
            f"{minimum_length} characters."
        )
    return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load settings without reading credentials from project files."""

    host = os.getenv("APP_HOST", "127.0.0.1")
    if host != "127.0.0.1":
        raise RuntimeError("APP_HOST must remain 127.0.0.1 for this local-only service.")

    try:
        port = int(os.getenv("APP_PORT", "8000"))
    except ValueError as error:
        raise RuntimeError("APP_PORT must be a valid integer.") from error

    if not 1 <= port <= 65535:
        raise RuntimeError("APP_PORT must be between 1 and 65535.")

    admin_username = os.getenv("APP_ADMIN_USERNAME", "local-admin").strip()
    if not admin_username:
        raise RuntimeError("APP_ADMIN_USERNAME must not be empty.")

    return Settings(
        host=host,
        port=port,
        admin_username=admin_username,
        admin_password=_required_environment_value("APP_ADMIN_PASSWORD", 12),
        session_secret=_required_environment_value("APP_SESSION_SECRET", 32),
        database_path=(
            Path(os.getenv("APP_DATA_DIRECTORY", Path(__file__).resolve().parent.parent / "data"))
            / "workbench.sqlite3"
        ).resolve(),
    )
