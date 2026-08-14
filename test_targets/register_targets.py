"""Register the bundled localhost-only permission targets without credentials."""

from __future__ import annotations

from pathlib import Path

from app.config import get_settings
from app.database import initialize_database
from app.projects import (
    add_asset,
    add_resource,
    add_role,
    add_target,
    add_test_account_mapping,
    create_project,
    list_assets,
    list_projects,
    list_resources,
    list_roles,
    list_targets,
    list_test_account_mappings,
    set_permission_rule,
)

PROJECT_NAME = "本地权限回归靶场"
ROOT = Path(__file__).resolve().parent
TARGETS = (
    ("code_directory", str((ROOT / "fastapi_target").resolve())),
    ("code_directory", str((ROOT / "node_target").resolve())),
    ("local_url", "http://127.0.0.1:8101"),
    ("local_url", "http://127.0.0.1:8102"),
)
ASSETS = (
    ("api", "FastAPI profile", "GET /api/profiles/{owner}"),
    ("api", "FastAPI order", "POST /api/orders/{owner}"),
    ("api", "Node profile", "GET /api/profiles/{owner}"),
    ("api", "Node order", "POST /api/orders/{owner}"),
    ("api", "Admin statistics", "GET /api/admin/stats"),
    ("dependency", "FastAPI target dependencies", "requirements.txt"),
    ("dependency", "Node target manifest", "package.json"),
)
RESOURCES = (
    ("查看 user-a 资料", "GET", "/api/profiles/user-a"),
    ("修改 user-a 订单", "POST", "/api/orders/user-a"),
    ("查看后台统计", "GET", "/api/admin/stats"),
)
EXPECTED_ACCESS = {
    "guest": ("deny", "deny", "deny"),
    "user-a": ("allow", "allow", "deny"),
    "user-b": ("deny", "deny", "deny"),
    "admin": ("allow", "allow", "allow"),
}


def _project_id(database_path: Path) -> int:
    for project in list_projects(database_path):
        if project.name == PROJECT_NAME:
            return project.id
    return create_project(
        database_path,
        PROJECT_NAME,
        "仅限 127.0.0.1 的 FastAPI 与 Node.js 权限回归靶场",
    ).id


def register_targets(database_path: Path) -> int:
    """Create an idempotent non-sensitive registration for the bundled targets."""

    initialize_database(database_path)
    project_id = _project_id(database_path)
    target_records = {(target.target_type, target.value) for target in list_targets(database_path, project_id)}
    for target_type, value in TARGETS:
        if (target_type, value) not in target_records:
            add_target(database_path, project_id, target_type, value)

    asset_records = {(asset.asset_type, asset.name) for asset in list_assets(database_path, project_id)}
    for asset_type, name, value in ASSETS:
        if (asset_type, name) not in asset_records:
            add_asset(database_path, project_id, asset_type, name, value)

    role_names = {row["name"] for row in list_roles(database_path, project_id)}
    for role in EXPECTED_ACCESS:
        if role not in role_names:
            add_role(database_path, project_id, role)

    resource_records = {(row["method"], row["endpoint"]) for row in list_resources(database_path, project_id)}
    for name, method, endpoint in RESOURCES:
        if (method, endpoint) not in resource_records:
            add_resource(database_path, project_id, name, method, endpoint)

    role_ids = {row["name"]: row["id"] for row in list_roles(database_path, project_id)}
    resource_ids = {row["endpoint"]: row["id"] for row in list_resources(database_path, project_id)}
    for role, expected_accesses in EXPECTED_ACCESS.items():
        for resource, expected_access in zip(RESOURCES, expected_accesses, strict=True):
            set_permission_rule(database_path, project_id, role_ids[role], resource_ids[resource[2]], expected_access)

    account_records = {
        (mapping.role_name, mapping.account_name) for mapping in list_test_account_mappings(database_path, project_id)
    }
    for role in ("user-a", "user-b", "admin"):
        for target_name, authentication_type in (("fastapi", "bearer"), ("node", "cookie")):
            account_name = f"{target_name}-{role}"
            if (role, account_name) not in account_records:
                add_test_account_mapping(
                    database_path,
                    project_id,
                    role_ids[role],
                    account_name,
                    authentication_type,
                    "runtime",
                )
    return project_id


if __name__ == "__main__":
    settings = get_settings()
    project_id = register_targets(settings.database_path)
    print(f"Registered local permission targets in project {project_id}.")
