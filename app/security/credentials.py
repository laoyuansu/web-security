"""Credential-vault boundary for future local test-account authentication."""

from __future__ import annotations

import keyring
from keyring.errors import KeyringError

SERVICE_PREFIX = "local-web-security-workbench"


class CredentialStoreError(RuntimeError):
    """Raised when the operating system credential vault is unavailable."""


def _service_name(project_id: str) -> str:
    normalized_project_id = project_id.strip()
    if not normalized_project_id:
        raise ValueError("project_id must not be empty.")
    return f"{SERVICE_PREFIX}:{normalized_project_id}"


def get_test_account_secret(project_id: str, account_name: str) -> str | None:
    """Read a test-account secret from the OS vault, never from SQLite or files."""

    try:
        return keyring.get_password(_service_name(project_id), account_name)
    except KeyringError as error:
        raise CredentialStoreError("The local credential vault is unavailable.") from error


def set_test_account_secret(project_id: str, account_name: str, secret: str) -> None:
    """Save a non-empty test-account secret in the OS vault."""

    if not account_name.strip() or not secret:
        raise ValueError("account_name and secret must not be empty.")
    try:
        keyring.set_password(_service_name(project_id), account_name, secret)
    except KeyringError as error:
        raise CredentialStoreError("The local credential vault is unavailable.") from error
