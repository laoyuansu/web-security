"""Tests for fail-closed, localhost-only runtime configuration."""

from __future__ import annotations

import pytest

from app.config import get_settings


def _clear_settings_cache() -> None:
    get_settings.cache_clear()


def test_default_host_is_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_HOST", raising=False)
    monkeypatch.setenv("APP_ADMIN_PASSWORD", "test-only-password")
    monkeypatch.setenv("APP_SESSION_SECRET", "s" * 32)
    _clear_settings_cache()

    assert get_settings().host == "127.0.0.1"


def test_non_loopback_host_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_HOST", "0.0.0.0")
    monkeypatch.setenv("APP_ADMIN_PASSWORD", "test-only-password")
    monkeypatch.setenv("APP_SESSION_SECRET", "s" * 32)
    _clear_settings_cache()

    with pytest.raises(RuntimeError, match="127.0.0.1"):
        get_settings()


def test_missing_secret_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_SESSION_SECRET", raising=False)
    monkeypatch.setenv("APP_ADMIN_PASSWORD", "test-only-password")
    _clear_settings_cache()

    with pytest.raises(RuntimeError, match="APP_SESSION_SECRET"):
        get_settings()
