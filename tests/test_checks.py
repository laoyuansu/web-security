"""Tests for bounded local security checks and non-secret evidence."""

from __future__ import annotations

import subprocess
from pathlib import Path

from app.checks import run_project_checks
from app.database import initialize_database
from app.projects import (
    ValidationError,
    add_target,
    create_project,
    create_remediation_task,
    delete_project,
    list_check_results,
    list_findings,
    list_remediation_tasks,
    record_regression_verification,
    update_finding_status,
    update_remediation_task_status,
)
from app.reports import build_markdown_report, build_redacted_backup, import_redacted_backup


def test_checks_record_redacted_secret_finding_for_registered_directory(tmp_path: Path) -> None:
    database_path = tmp_path / "workbench.sqlite3"
    source_directory = tmp_path / "authorized-project"
    source_directory.mkdir()
    test_value = "sk-" + "abcdefghijklmnopqrstuvwx"
    (source_directory / "settings.py").write_text(f"key = '{test_value}'\n", encoding="utf-8")
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
    update_remediation_task_status(database_path, project.id, findings[0].id, "done")
    try:
        update_finding_status(database_path, project.id, findings[0].id, "fixed")
    except ValidationError as error:
        assert "回归验证" in str(error)
    else:
        raise AssertionError("Fixed findings must require a passed regression verification.")
    record_regression_verification(database_path, project.id, findings[0].id, "passed", "自动化回归通过，未记录凭据。")
    update_finding_status(database_path, project.id, findings[0].id, "fixed")
    assert "安全自查报告" in build_markdown_report(database_path, project.id)
    assert '"credential_data_included": false' in build_redacted_backup(database_path, project.id)
    imported = import_redacted_backup(database_path, build_redacted_backup(database_path, project.id))
    assert imported.name.endswith("（导入）")
    duplicate_import = import_redacted_backup(database_path, build_redacted_backup(database_path, project.id))
    assert duplicate_import.name.endswith("（导入） 2")


def test_checks_skip_unregistered_targets(tmp_path: Path) -> None:
    database_path = tmp_path / "workbench.sqlite3"
    initialize_database(database_path)
    project = create_project(database_path, "无目标项目", "")

    run_project_checks(database_path, project.id)

    results = list_check_results(database_path, project.id)
    assert len(results) == 4
    assert {result.outcome for result in results} == {"skipped"}


def test_checks_detect_redacted_secret_signatures_in_authorized_git_history(tmp_path: Path) -> None:
    database_path = tmp_path / "workbench.sqlite3"
    source_directory = tmp_path / "authorized-project"
    source_directory.mkdir()
    historic_value = "sk-" + "x" * 24
    history_file = source_directory / "removed-secret.py"
    history_file.write_text(f"value = '{historic_value}'\n", encoding="utf-8")
    for command in (
        ["git", "init"],
        ["git", "config", "user.name", "test"],
        ["git", "config", "user.email", "test@example.invalid"],
        ["git", "add", "removed-secret.py"],
        ["git", "commit", "-m", "add temporary test value"],
    ):
        subprocess.run(command, cwd=source_directory, check=True, capture_output=True, text=True)
    history_file.unlink()
    subprocess.run(["git", "add", "-A"], cwd=source_directory, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "commit", "-m", "remove temporary test value"],
        cwd=source_directory,
        check=True,
        capture_output=True,
        text=True,
    )
    initialize_database(database_path)
    project = create_project(database_path, "历史检查项目", "")
    add_target(database_path, project.id, "code_directory", str(source_directory))

    run_project_checks(database_path, project.id)

    history_findings = [item for item in list_findings(database_path, project.id) if item.module == "Git 历史"]
    assert history_findings
    assert all(historic_value not in item.evidence for item in history_findings)
    secret_result = next(
        item for item in list_check_results(database_path, project.id) if item.check_type == "secret_leak"
    )
    assert "Git 历史" in secret_result.detail


def test_project_deletion_requires_an_exact_project_name(tmp_path: Path) -> None:
    database_path = tmp_path / "workbench.sqlite3"
    initialize_database(database_path)
    project = create_project(database_path, "待删除项目", "")
    try:
        delete_project(database_path, project.id, "错误名称")
    except ValidationError:
        pass
    else:
        raise AssertionError("Deletion must require an exact confirmation name.")
    delete_project(database_path, project.id, "待删除项目")
