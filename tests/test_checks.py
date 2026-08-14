"""Tests for bounded local security checks and non-secret evidence."""

from __future__ import annotations

from pathlib import Path

from app.checks import run_project_checks
from app.database import initialize_database
from app.projects import (
    add_target,
    create_project,
    create_remediation_task,
    list_check_results,
    list_findings,
    list_remediation_tasks,
    update_finding_status,
)
from app.reports import build_markdown_report, build_redacted_backup


def test_checks_record_redacted_secret_finding_for_registered_directory(tmp_path: Path) -> None:
    database_path = tmp_path / "workbench.sqlite3"
    source_directory = tmp_path / "authorized-project"
    source_directory.mkdir()
    (source_directory / "settings.py").write_text("key = 'sk-abcdefghijklmnopqrstuvwx'\n", encoding="utf-8")
    initialize_database(database_path)
    project = create_project(database_path, "检查项目", "")
    add_target(database_path, project.id, "code_directory", str(source_directory))

    run_project_checks(database_path, project.id)

    findings = list_findings(database_path, project.id)
    results = list_check_results(database_path, project.id)
    assert findings[0].finding_type == "secret_leak"
    assert "abcdefghijkl" not in findings[0].evidence
    assert {result.check_type for result in results} == {
        "secret_leak", "dependency", "configuration", "http_baseline"
    }
    update_finding_status(database_path, project.id, findings[0].id, "confirmed")
    create_remediation_task(database_path, findings[0].id, "测试根因", "测试修复建议")
    assert list_remediation_tasks(database_path, project.id)[0].finding_id == findings[0].id
    assert "安全自查报告" in build_markdown_report(database_path, project.id)
    assert '"credential_data_included": false' in build_redacted_backup(database_path, project.id)


def test_checks_skip_unregistered_targets(tmp_path: Path) -> None:
    database_path = tmp_path / "workbench.sqlite3"
    initialize_database(database_path)
    project = create_project(database_path, "无目标项目", "")

    run_project_checks(database_path, project.id)

    results = list_check_results(database_path, project.id)
    assert len(results) == 4
    assert {result.outcome for result in results} == {"skipped"}
