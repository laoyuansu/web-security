"""Tests for project-isolated permission-matrix configuration."""

from pathlib import Path

from app.database import initialize_database
from app.projects import (
    add_resource,
    add_role,
    add_test_account_mapping,
    create_project,
    list_matrix_rows,
    list_resources,
    list_roles,
    list_test_account_mappings,
    set_permission_rule,
)


def test_permission_rules_are_project_scoped(tmp_path: Path) -> None:
    database_path = tmp_path / "workbench.sqlite3"
    initialize_database(database_path)
    project = create_project(database_path, "权限项目", "")
    add_role(database_path, project.id, "管理员")
    add_resource(database_path, project.id, "统计", "GET", "/api/stats")
    role_id = list_roles(database_path, project.id)[0]["id"]
    resource_id = list_resources(database_path, project.id)[0]["id"]
    set_permission_rule(database_path, project.id, role_id, resource_id, "allow")

    assert list_matrix_rows(database_path, project.id)[0].expected_access == "allow"
    add_test_account_mapping(database_path, project.id, role_id, "admin-test", "cookie", "runtime")
    assert list_test_account_mappings(database_path, project.id)[0].account_name == "admin-test"
