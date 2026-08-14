"""Tests for independent local login, logout, and CSRF protection."""

from __future__ import annotations

import os
import re
from pathlib import Path

from fastapi.testclient import TestClient


def create_test_app(database_path: Path):
    """Create an isolated app after supplying non-secret test-only values."""

    os.environ["APP_ADMIN_PASSWORD"] = "test-only-password"
    os.environ["APP_SESSION_SECRET"] = "s" * 32
    from app.config import Settings
    from app.main import create_app

    return create_app(
        Settings(
            host="127.0.0.1",
            port=8000,
            admin_username="local-admin",
            admin_password="test-only-password",
            session_secret="s" * 32,
            database_path=database_path,
        )
    )


def _csrf_token(response_text: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response_text)
    assert match is not None
    return match.group(1)


def test_dashboard_requires_login(tmp_path: Path) -> None:
    with TestClient(create_test_app(tmp_path / "workbench.sqlite3")) as client:
        response = client.get("/dashboard", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_login_and_logout_flow(tmp_path: Path) -> None:
    with TestClient(create_test_app(tmp_path / "workbench.sqlite3")) as client:
        login_page = client.get("/login")
        login_response = client.post(
            "/login",
            data={
                "csrf_token": _csrf_token(login_page.text),
                "username": "local-admin",
                "password": "test-only-password",
            },
            follow_redirects=False,
        )
        assert login_response.status_code == 303

        dashboard = client.get("/dashboard")
        logout_response = client.post(
            "/logout",
            data={"csrf_token": _csrf_token(dashboard.text)},
            follow_redirects=False,
        )
        assert logout_response.status_code == 303
        assert client.get("/dashboard", follow_redirects=False).status_code == 303


def test_login_rejects_invalid_csrf_token(tmp_path: Path) -> None:
    with TestClient(create_test_app(tmp_path / "workbench.sqlite3")) as client:
        response = client.post(
            "/login",
            data={"csrf_token": "invalid", "username": "local-admin", "password": "test-only-password"},
        )

    assert response.status_code == 403
