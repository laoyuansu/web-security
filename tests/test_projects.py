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


def test_matrix_routes_save_rules_and_skip_unmapped_accounts(tmp_path: Path) -> None:
    database_path = tmp_path / "workbench.sqlite3"
    with TestClient(create_test_app(database_path)) as client:
        login(client)
        project_id = create_project(client, "矩阵路由")
        page = client.get(f"/projects/{project_id}/matrix")
        role_response = client.post(
            f"/projects/{project_id}/matrix/roles",
            data={"csrf_token": csrf_token(page.text), "name": "测试角色"},
            follow_redirects=False,
        )
        assert role_response.status_code == 303

        page = client.get(f"/projects/{project_id}/matrix")
        resource_response = client.post(
            f"/projects/{project_id}/matrix/resources",
            data={
                "csrf_token": csrf_token(page.text),
                "name": "测试资源",
                "method": "GET",
                "endpoint": "/api/testing",
            },
            follow_redirects=False,
        )
        assert resource_response.status_code == 303

        from app.projects import list_resources, list_roles

        role_id = list_roles(database_path, project_id)[0]["id"]
        resource_id = list_resources(database_path, project_id)[0]["id"]
        page = client.get(f"/projects/{project_id}/matrix")
        rule_response = client.post(
            f"/projects/{project_id}/matrix/rules",
            data={
                "csrf_token": csrf_token(page.text),
                "role_id": role_id,
                "resource_id": resource_id,
                "expected_access": "deny",
            },
            follow_redirects=False,
        )
        assert rule_response.status_code == 303

        page = client.get(f"/projects/{project_id}/matrix")
        run_response = client.post(
            f"/projects/{project_id}/matrix/run",
            data={"csrf_token": csrf_token(page.text)},
            follow_redirects=False,
        )

    assert run_response.status_code == 303


def test_findings_page_requires_regression_before_closing_a_finding(tmp_path: Path) -> None:
    database_path = tmp_path / "workbench.sqlite3"
    with TestClient(create_test_app(database_path)) as client:
        login(client)
        project_id = create_project(client, "修复闭环")
        from app.projects import create_check_run, finish_check_run, record_finding

        run_id = create_check_run(database_path, project_id)
        record_finding(
            database_path,
            project_id,
            run_id,
            "测试发现",
            "api/orders",
            "permission_matrix",
            "high",
            "仅测试用的非敏感证据。",
            "拒绝无权访问。",
            "测试结果待确认。",
        )
        finish_check_run(database_path, run_id)
        page = client.get(f"/projects/{project_id}/findings")
        assert "测试发现" in page.text

        task_response = client.post(
            f"/projects/{project_id}/findings/1/tasks",
            data={
                "csrf_token": csrf_token(page.text),
                "root_cause": "测试根因",
                "recommendation": "测试修复建议",
                "owner": "本地负责人",
                "due_date": "2026-08-16",
            },
            follow_redirects=False,
        )
        assert task_response.status_code == 303

        page = client.get(f"/projects/{project_id}/findings")
        premature_close = client.post(
            f"/projects/{project_id}/findings/1/status",
            data={"csrf_token": csrf_token(page.text), "status": "fixed"},
        )
        assert premature_close.status_code == 422
        assert "回归验证" in premature_close.text

        page = client.get(f"/projects/{project_id}/findings")
        verification_response = client.post(
            f"/projects/{project_id}/findings/1/verifications",
            data={
                "csrf_token": csrf_token(page.text),
                "outcome": "passed",
                "detail": "自动化回归通过，未记录凭据。",
            },
            follow_redirects=False,
        )
        assert verification_response.status_code == 303

        page = client.get(f"/projects/{project_id}/findings")
        close_response = client.post(
            f"/projects/{project_id}/findings/1/status",
            data={"csrf_token": csrf_token(page.text), "status": "fixed"},
            follow_redirects=False,
        )
        assert close_response.status_code == 303
        assert "fixed" in client.get(f"/projects/{project_id}/findings").text


def test_report_page_imports_only_a_redacted_json_backup(tmp_path: Path) -> None:
    with TestClient(create_test_app(tmp_path / "workbench.sqlite3")) as client:
        login(client)
        project_id = create_project(client, "备份来源")
        backup = client.get(f"/projects/{project_id}/backup.json")
        report_page = client.get(f"/projects/{project_id}/report")
        imported = client.post(
            f"/projects/{project_id}/backup/import",
            data={"csrf_token": csrf_token(report_page.text)},
            files={"backup_file": ("backup.json", backup.content, "application/json")},
            follow_redirects=False,
        )
        assert imported.status_code == 303
        assert "（导入）" in client.get(imported.headers["location"]).text

        report_page = client.get(f"/projects/{project_id}/report")
        rejected = client.post(
            f"/projects/{project_id}/backup/import",
            data={"csrf_token": csrf_token(report_page.text)},
            files={
                "backup_file": (
                    "unsafe.json",
                    b'{"format":"local-web-security-workbench-backup-v1","credential_data_included":false,"token":"not-allowed"}',
                    "application/json",
                )
            },
        )
        assert rejected.status_code == 422
        assert "禁止" in rejected.text
