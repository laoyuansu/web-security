"""Markdown reports and deliberately credential-free JSON backups."""

from __future__ import annotations

import json
from pathlib import Path

from app.projects import (
    add_asset,
    create_project,
    get_project,
    list_assets,
    list_check_results,
    list_findings,
    list_import_records,
    list_projects,
    list_regression_verifications,
    list_remediation_tasks,
)


def import_redacted_backup(database_path: Path, source_text: str):
    """Import only the documented credential-free backup shape as a new project."""

    document = json.loads(source_text)
    forbidden = {"password", "token", "cookie", "secret", "credential"}
    if not isinstance(document, dict) or document.get("format") != "local-web-security-workbench-backup-v1":
        raise ValueError("不支持的备份格式。")
    if document.get("credential_data_included") is not False:
        raise ValueError("备份必须明确声明不包含凭据。")
    if any(key in forbidden for key in document):
        raise ValueError("备份包含禁止的凭据字段。")
    project_data = document.get("project")
    if not isinstance(project_data, dict):
        raise TypeError("备份缺少项目元数据。")
    base_name = str(project_data.get("name", "")).strip() + "（导入）"
    existing_names = {project.name for project in list_projects(database_path)}
    imported_name = base_name
    suffix = 2
    while imported_name in existing_names:
        imported_name = f"{base_name} {suffix}"
        suffix += 1
    project = create_project(database_path, imported_name, str(project_data.get("description", "")))
    for asset in document.get("assets", []):
        if isinstance(asset, dict):
            add_asset(database_path, project.id, str(asset.get("type", "")), str(asset.get("name", "")), str(asset.get("value", "")))
    return project


def build_markdown_report(database_path: Path, project_id: int) -> str:
    project = get_project(database_path, project_id)
    if project is None:
        raise ValueError("项目不存在。")
    lines = [f"# 安全自查报告：{project.name}", "", "## 检查结果"]
    lines += [f"- {item.check_type}: {item.outcome} — {item.detail}" for item in list_check_results(database_path, project_id)] or ["- 暂无检查记录。"]
    lines += ["", "## 发现"]
    findings = list_findings(database_path, project_id)
    tasks = {item.finding_id: item for item in list_remediation_tasks(database_path, project_id)}
    verifications: dict[int, list] = {}
    for verification in list_regression_verifications(database_path, project_id):
        verifications.setdefault(verification.finding_id, []).append(verification)
    if not findings:
        lines += ["- 暂无发现。"]
    for item in findings:
        lines += [
            f"### [{item.severity}] {item.title}",
            f"- 状态：{item.status}",
            f"- 受影响模块：{item.module}",
            f"- 发现类型：{item.finding_type}",
            f"- 证据与时间：{item.evidence}（{item.created_at}）",
            f"- 预期行为：{item.expected}",
            f"- 实际行为：{item.actual}",
        ]
        task = tasks.get(item.id)
        if task:
            lines += [
                f"- 根因：{task.root_cause}",
                f"- 修复建议：{task.recommendation}",
                f"- 负责人/截止时间：{task.owner or '未分配'} / {task.due_date or '未设置'}",
                f"- 修复任务状态：{task.status}",
            ]
        else:
            lines += ["- 根因与修复建议：尚未创建修复任务。"]
        current_verifications = verifications.get(item.id, [])
        lines += [
            f"- 回归验证：{verification.outcome} — {verification.detail}（{verification.created_at}）"
            for verification in current_verifications
        ] or ["- 回归验证：暂无记录。"]
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
