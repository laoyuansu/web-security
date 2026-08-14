"""Markdown reports and deliberately credential-free JSON backups."""

from __future__ import annotations

import json
from pathlib import Path

from app.projects import (
    get_project,
    list_assets,
    list_check_results,
    list_findings,
    list_import_records,
    list_remediation_tasks,
)


def build_markdown_report(database_path: Path, project_id: int) -> str:
    project = get_project(database_path, project_id)
    if project is None:
        raise ValueError("项目不存在。")
    lines = [f"# 安全自查报告：{project.name}", "", "## 检查结果"]
    lines += [f"- {item.check_type}: {item.outcome} — {item.detail}" for item in list_check_results(database_path, project_id)] or ["- 暂无检查记录。"]
    lines += ["", "## 发现"]
    lines += [f"- [{item.severity}] {item.title}（{item.status}）：{item.evidence}" for item in list_findings(database_path, project_id)] or ["- 暂无发现。"]
    lines += ["", "## 修复任务"]
    lines += [f"- 发现 #{item.finding_id}: {item.status}，{item.recommendation}" for item in list_remediation_tasks(database_path, project_id)] or ["- 暂无修复任务。"]
    lines += ["", "## 导入历史"]
    lines += [f"- {item.source_kind}: {item.outcome} — {item.detail}" for item in list_import_records(database_path, project_id)] or ["- 暂无导入记录。"]
    return "\n".join(lines) + "\n"


def build_redacted_backup(database_path: Path, project_id: int) -> str:
    project = get_project(database_path, project_id)
    if project is None:
        raise ValueError("项目不存在。")
    document = {
        "format": "local-web-security-workbench-backup-v1",
        "project": {"name": project.name, "description": project.description},
        "assets": [{"type": item.asset_type, "name": item.name, "value": item.value} for item in list_assets(database_path, project_id)],
        "findings": [{"title": item.title, "type": item.finding_type, "severity": item.severity, "status": item.status} for item in list_findings(database_path, project_id)],
        "credential_data_included": False,
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"
