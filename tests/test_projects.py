"""Tests for project-scoped asset registration and target-boundary validation."""

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


def csrf_token(response_text: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', response_text)
    assert match is not None
    return match.group(1)


def login(client: TestClient) -> None:
    page = client.get("/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf_token(page.text),
            "username": "local-admin",
            "password": "test-only-password",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


def create_project(client: TestClient, name: str) -> int:
    page = client.get("/projects")
    response = client.post(
        "/projects",
        data={"csrf_token": csrf_token(page.text), "name": name, "description": "本地测试项目"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return int(response.headers["location"].rsplit("/", maxsplit=1)[1])


def test_projects_require_login(tmp_path: Path) -> None:
    with TestClient(create_test_app(tmp_path / "workbench.sqlite3")) as client:
        response = client.get("/projects", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_registers_local_project_target_and_asset(tmp_path: Path) -> None:
    source_directory = tmp_path / "authorized-project"
    source_directory.mkdir()
    with TestClient(create_test_app(tmp_path / "workbench.sqlite3")) as client:
        login(client)
        project_id = create_project(client, "自查台")
        detail_page = client.get(f"/projects/{project_id}")
        target_response = client.post(
            f"/projects/{project_id}/targets",
            data={
                "csrf_token": csrf_token(detail_page.text),
                "target_type": "code_directory",
                "value": str(source_directory),
            },
            follow_redirects=False,
        )
        assert target_response.status_code == 303

        detail_page = client.get(f"/projects/{project_id}")
        asset_response = client.post(
            f"/projects/{project_id}/assets",
            data={
                "csrf_token": csrf_token(detail_page.text),
                "asset_type": "api",
                "name": "本地资料接口",
                "value": "/api/profile",
            },
            follow_redirects=False,
        )
        assert asset_response.status_code == 303
        detail = client.get(f"/projects/{project_id}")

    assert str(source_directory.resolve()) in detail.text
    assert "本地资料接口" in detail.text


def test_rejects_public_url_and_does_not_add_target(tmp_path: Path) -> None:
    with TestClient(create_test_app(tmp_path / "workbench.sqlite3")) as client:
        login(client)
        project_id = create_project(client, "范围校验")
        page = client.get(f"/projects/{project_id}")
        response = client.post(
            f"/projects/{project_id}/targets",
            data={
                "csrf_token": csrf_token(page.text),
                "target_type": "local_url",
                "value": "https://example.com",
            },
        )

    assert response.status_code == 422
    assert "仅允许" in response.text


def test_assets_are_isolated_by_project(tmp_path: Path) -> None:
    with TestClient(create_test_app(tmp_path / "workbench.sqlite3")) as client:
        login(client)
        first_project_id = create_project(client, "项目 A")
        second_project_id = create_project(client, "项目 B")
        first_page = client.get(f"/projects/{first_project_id}")
        client.post(
            f"/projects/{first_project_id}/assets",
            data={
                "csrf_token": csrf_token(first_page.text),
                "asset_type": "dependency",
                "name": "fastapi",
                "value": "测试依赖",
            },
            follow_redirects=False,
        )
        second_project_page = client.get(f"/projects/{second_project_id}")

    assert "fastapi" not in second_project_page.text
