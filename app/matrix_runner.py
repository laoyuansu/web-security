"""Execute only registered local permission-matrix requests without retaining credentials."""

from __future__ import annotations

from pathlib import Path

from app.permission_runner import execute_permission_request
from app.projects import (
    create_check_run,
    create_permission_regression_run,
    finish_check_run,
    finish_permission_regression_run,
    list_matrix_rows,
    list_test_account_mappings,
    record_finding,
    record_permission_regression_result,
)
from app.security.credentials import CredentialStoreError, get_test_account_secret


def run_permission_matrix(database_path: Path, project_id: int) -> None:
    """Run vault-backed mappings; runtime-only accounts are explicitly skipped."""

    run_id = create_permission_regression_run(database_path, project_id)
    finding_run_id = create_check_run(database_path, project_id)
    try:
        mappings = list_test_account_mappings(database_path, project_id)
        for rule in list_matrix_rows(database_path, project_id):
            matching_accounts = [mapping for mapping in mappings if mapping.role_name == rule.role_name]
            if not matching_accounts:
                record_permission_regression_result(database_path, run_id, rule.role_name, "", "", rule.method, rule.endpoint, rule.expected_access, "skipped", None, "未配置该角色的本地测试账号；未发起请求。")
                continue
            for mapping in matching_accounts:
                if not mapping.target_url:
                    record_permission_regression_result(database_path, run_id, mapping.role_name, mapping.account_name, "", rule.method, rule.endpoint, rule.expected_access, "skipped", None, "测试账号未关联已登记本地 URL；未发起请求。")
                    continue
                if mapping.credential_source == "runtime":
                    record_permission_regression_result(database_path, run_id, mapping.role_name, mapping.account_name, mapping.target_url, rule.method, rule.endpoint, rule.expected_access, "skipped", None, "账号需要运行时凭据；本次未收集或保存凭据。")
                    continue
                try:
                    credential = get_test_account_secret(str(project_id), mapping.account_name)
                except CredentialStoreError:
                    credential = None
                result = execute_permission_request(mapping.target_url, rule.endpoint, rule.method, rule.expected_access, mapping.authentication_type, credential)
                record_permission_regression_result(database_path, run_id, mapping.role_name, mapping.account_name, mapping.target_url, rule.method, rule.endpoint, rule.expected_access, result.outcome, result.status_code, result.detail)
                if result.outcome == "failed":
                    record_finding(database_path, project_id, finding_run_id, "权限矩阵规则与实际不符", f"{rule.method} {rule.endpoint}", "permission_matrix", "high", result.detail, f"{mapping.role_name} 应为 {rule.expected_access}", "服务端实际结果与矩阵预期不一致。")
    except Exception:
        finish_permission_regression_run(database_path, run_id, "failed")
        finish_check_run(database_path, finding_run_id, "failed")
        raise
    finish_permission_regression_run(database_path, run_id)
    finish_check_run(database_path, finding_run_id)
