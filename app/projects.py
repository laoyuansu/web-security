"""Project-scoped metadata validation and SQLite access helpers."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from app.database import connect

TARGET_TYPES = {"code_directory", "local_url", "docker_address"}
ASSET_TYPES = {"page", "api", "data_type", "dependency", "docker_service"}
IMPORT_SOURCE_KINDS = {"openapi", "requirements", "package_json", "docker_compose"}
IMPORT_OUTCOMES = {"imported", "skipped", "error"}
LOCAL_HOSTNAMES = {"localhost", "127.0.0.1"}
DOCKER_BRIDGE_NETWORK = ipaddress.ip_network("172.16.0.0/12")


class ValidationError(ValueError):
    """Raised when user-provided project metadata is out of permitted scope."""


@dataclass(frozen=True)
class Project:
    id: int
    name: str
    description: str
    created_at: str


@dataclass(frozen=True)
class ProjectTarget:
    id: int
    project_id: int
    target_type: str
    value: str
    created_at: str


@dataclass(frozen=True)
class Asset:
    id: int
    project_id: int
    asset_type: str
    name: str
    value: str
    created_at: str


@dataclass(frozen=True)
class ImportRecord:
    id: int
    project_id: int
    source_kind: str
    source_path: str
    outcome: str
    detail: str
    created_at: str


@dataclass(frozen=True)
class CheckResult:
    check_type: str
    outcome: str
    detail: str


@dataclass(frozen=True)
class Finding:
    id: int
    title: str
    module: str
    finding_type: str
    severity: str
    evidence: str
    expected: str
    actual: str
    status: str
    created_at: str


@dataclass(frozen=True)
class RemediationTask:
    finding_id: int
    root_cause: str
    recommendation: str
    owner: str
    due_date: str
    status: str


@dataclass(frozen=True)
class RegressionVerification:
    finding_id: int
    outcome: str
    detail: str
    created_at: str


@dataclass(frozen=True)
class MatrixRow:
    role_name: str
    resource_name: str
    method: str
    endpoint: str
    expected_access: str


@dataclass(frozen=True)
class TestAccountMapping:
    role_name: str
    account_name: str
    target_url: str
    authentication_type: str
    credential_source: str


@dataclass(frozen=True)
class PermissionRegressionResult:
    role_name: str
    account_name: str
    target_url: str
    method: str
    endpoint: str
    expected_access: str
    outcome: str
    status_code: int | None
    detail: str
    created_at: str


def _project_from_row(row) -> Project:
    return Project(**dict(row))


def _target_from_row(row) -> ProjectTarget:
    return ProjectTarget(**dict(row))


def _asset_from_row(row) -> Asset:
    return Asset(**dict(row))


def _import_record_from_row(row) -> ImportRecord:
    return ImportRecord(**dict(row))


def validate_project(name: str, description: str) -> tuple[str, str]:
    """Validate bounded project metadata before inserting it into SQLite."""

    normalized_name = name.strip()
    normalized_description = description.strip()
    if not 1 <= len(normalized_name) <= 120:
        raise ValidationError("项目名称必须为 1 至 120 个字符。")
    if len(normalized_description) > 1_000:
        raise ValidationError("项目说明不能超过 1000 个字符。")
    return normalized_name, normalized_description


def validate_target(target_type: str, value: str) -> str:
    """Reject targets outside the project's localhost and Docker-only boundary."""

    normalized_value = value.strip()
    if target_type not in TARGET_TYPES:
        raise ValidationError("不支持的目标类型。")
    if not normalized_value:
        raise ValidationError("目标地址或目录不能为空。")

    if target_type == "code_directory":
        directory = Path(normalized_value).resolve()
        if not directory.is_absolute() or not directory.is_dir() or directory == Path(directory.anchor):
            raise ValidationError("代码目录必须是存在的非根目录绝对路径。")
        return str(directory)

    parsed_url = urlparse(normalized_value)
    if target_type == "local_url":
        if (
            parsed_url.scheme not in {"http", "https"}
            or parsed_url.hostname not in LOCAL_HOSTNAMES
            or parsed_url.username
            or parsed_url.password
        ):
            raise ValidationError("本地 URL 仅允许 http(s)://localhost 或 127.0.0.1，且不得包含凭据。")
        try:
            _ = parsed_url.port
        except ValueError as error:
            raise ValidationError("本地 URL 端口无效。") from error
        return normalized_value

    if parsed_url.scheme or "/" in normalized_value or ":" in normalized_value:
        raise ValidationError("Docker 地址必须是 IP 地址，不包含协议、端口或路径。")
    try:
        docker_address = ipaddress.ip_address(normalized_value)
    except ValueError as error:
        raise ValidationError("Docker 地址必须是有效 IP 地址。") from error
    if docker_address not in DOCKER_BRIDGE_NETWORK:
        raise ValidationError("仅允许登记 172.16.0.0/12 范围内的本地 Docker 网桥地址。")
    return str(docker_address)


def validate_asset(asset_type: str, name: str, value: str) -> tuple[str, str, str]:
    """Validate a small, project-scoped asset record."""

    normalized_name = name.strip()
    normalized_value = value.strip()
    if asset_type not in ASSET_TYPES:
        raise ValidationError("不支持的资产类型。")
    if not 1 <= len(normalized_name) <= 160:
        raise ValidationError("资产名称必须为 1 至 160 个字符。")
    if len(normalized_value) > 1_000:
        raise ValidationError("资产说明不能超过 1000 个字符。")
    return asset_type, normalized_name, normalized_value


def list_projects(database_path: Path) -> list[Project]:
    with connect(database_path) as connection:
        rows = connection.execute("SELECT * FROM projects ORDER BY id DESC").fetchall()
    return [_project_from_row(row) for row in rows]


def get_project(database_path: Path, project_id: int) -> Project | None:
    with connect(database_path) as connection:
        row = connection.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    return _project_from_row(row) if row else None


def create_project(database_path: Path, name: str, description: str) -> Project:
    normalized_name, normalized_description = validate_project(name, description)
    try:
        with connect(database_path) as connection:
            cursor = connection.execute(
                "INSERT INTO projects (name, description) VALUES (?, ?)",
                (normalized_name, normalized_description),
            )
            row = connection.execute("SELECT * FROM projects WHERE id = ?", (cursor.lastrowid,)).fetchone()
    except Exception as error:
        if "UNIQUE constraint failed" in str(error):
            raise ValidationError("项目名称已存在。") from error
        raise
    assert row is not None
    return _project_from_row(row)


def delete_project(database_path: Path, project_id: int, confirmation_name: str) -> None:
    """Delete one project and its cascaded local history after an exact-name confirmation."""

    project = get_project(database_path, project_id)
    if project is None:
        raise ValidationError("项目不存在。")
    if project.name != confirmation_name.strip():
        raise ValidationError("确认名称与项目名称不一致；未删除任何数据。")
    with connect(database_path) as connection:
        connection.execute("DELETE FROM projects WHERE id = ?", (project_id,))


def list_targets(database_path: Path, project_id: int) -> list[ProjectTarget]:
    with connect(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM project_targets WHERE project_id = ? ORDER BY id DESC", (project_id,)
        ).fetchall()
    return [_target_from_row(row) for row in rows]


def list_code_directories(database_path: Path, project_id: int) -> list[Path]:
    """Return only project-authorized code roots for local file discovery."""

    return [
        Path(target.value)
        for target in list_targets(database_path, project_id)
        if target.target_type == "code_directory"
    ]


def add_target(database_path: Path, project_id: int, target_type: str, value: str) -> ProjectTarget:
    normalized_value = validate_target(target_type, value)
    try:
        with connect(database_path) as connection:
            cursor = connection.execute(
                "INSERT INTO project_targets (project_id, target_type, value) VALUES (?, ?, ?)",
                (project_id, target_type, normalized_value),
            )
            row = connection.execute("SELECT * FROM project_targets WHERE id = ?", (cursor.lastrowid,)).fetchone()
    except Exception as error:
        if "UNIQUE constraint failed" in str(error):
            raise ValidationError("该目标已登记。") from error
        raise
    assert row is not None
    return _target_from_row(row)


def list_assets(database_path: Path, project_id: int) -> list[Asset]:
    with connect(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM assets WHERE project_id = ? ORDER BY id DESC", (project_id,)
        ).fetchall()
    return [_asset_from_row(row) for row in rows]


def add_asset(database_path: Path, project_id: int, asset_type: str, name: str, value: str) -> Asset:
    normalized_type, normalized_name, normalized_value = validate_asset(asset_type, name, value)
    try:
        with connect(database_path) as connection:
            cursor = connection.execute(
                "INSERT INTO assets (project_id, asset_type, name, value) VALUES (?, ?, ?, ?)",
                (project_id, normalized_type, normalized_name, normalized_value),
            )
            row = connection.execute("SELECT * FROM assets WHERE id = ?", (cursor.lastrowid,)).fetchone()
    except Exception as error:
        if "UNIQUE constraint failed" in str(error):
            raise ValidationError("该项目中已存在同类型同名称资产。") from error
        raise
    assert row is not None
    return _asset_from_row(row)


def record_import(
    database_path: Path,
    project_id: int,
    source_kind: str,
    source_path: str,
    outcome: str,
    detail: str,
) -> ImportRecord:
    """Persist a non-sensitive import outcome for a single project."""

    if source_kind not in IMPORT_SOURCE_KINDS or outcome not in IMPORT_OUTCOMES:
        raise ValueError("Unsupported import record values.")
    with connect(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO import_records (project_id, source_kind, source_path, outcome, detail)
            VALUES (?, ?, ?, ?, ?)
            """,
            (project_id, source_kind, source_path, outcome, detail[:1_000]),
        )
        row = connection.execute("SELECT * FROM import_records WHERE id = ?", (cursor.lastrowid,)).fetchone()
    assert row is not None
    return _import_record_from_row(row)


def list_import_records(database_path: Path, project_id: int) -> list[ImportRecord]:
    with connect(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM import_records WHERE project_id = ? ORDER BY id DESC LIMIT 50", (project_id,)
        ).fetchall()
    return [_import_record_from_row(row) for row in rows]


def create_check_run(database_path: Path, project_id: int) -> int:
    with connect(database_path) as connection:
        cursor = connection.execute("INSERT INTO check_runs (project_id, status) VALUES (?, 'running')", (project_id,))
    return int(cursor.lastrowid)


def finish_check_run(database_path: Path, run_id: int, status: str = "completed") -> None:
    with connect(database_path) as connection:
        connection.execute(
            "UPDATE check_runs SET status = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?", (status, run_id)
        )


def record_check_result(
    database_path: Path, run_id: int, check_type: str, outcome: str, detail: str
) -> None:
    with connect(database_path) as connection:
        connection.execute(
            "INSERT INTO check_results (check_run_id, check_type, outcome, detail) VALUES (?, ?, ?, ?)",
            (run_id, check_type, outcome, detail[:1_000]),
        )


def record_finding(
    database_path: Path,
    project_id: int,
    run_id: int,
    title: str,
    module: str,
    finding_type: str,
    severity: str,
    evidence: str,
    expected: str,
    actual: str,
) -> None:
    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO findings (
                project_id, check_run_id, title, module, finding_type, severity, evidence, expected, actual
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (project_id, run_id, title, module, finding_type, severity, evidence[:1_000], expected, actual),
        )


def list_check_results(database_path: Path, project_id: int) -> list[CheckResult]:
    with connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT check_type, outcome, detail FROM check_results
            INNER JOIN check_runs ON check_runs.id = check_results.check_run_id
            WHERE check_runs.project_id = ? ORDER BY check_results.id DESC LIMIT 20
            """,
            (project_id,),
        ).fetchall()
    return [CheckResult(**dict(row)) for row in rows]


def list_findings(database_path: Path, project_id: int) -> list[Finding]:
    with connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT id, title, module, finding_type, severity, evidence, expected, actual, status, created_at
            FROM findings WHERE project_id = ? ORDER BY id DESC LIMIT 50
            """,
            (project_id,),
        ).fetchall()
    return [Finding(**dict(row)) for row in rows]


def update_finding_status(database_path: Path, project_id: int, finding_id: int, status: str) -> None:
    if status not in {"pending", "confirmed", "false_positive", "fixed"}:
        raise ValidationError("发现状态无效。")
    with connect(database_path) as connection:
        if status == "fixed":
            verification = connection.execute(
                """
                SELECT 1 FROM regression_verifications
                JOIN findings ON findings.id = regression_verifications.finding_id
                WHERE findings.project_id = ? AND findings.id = ?
                  AND regression_verifications.outcome = 'passed'
                LIMIT 1
                """,
                (project_id, finding_id),
            ).fetchone()
            if verification is None:
                raise ValidationError("关闭发现前必须记录一次通过的回归验证。")
        cursor = connection.execute("UPDATE findings SET status = ? WHERE id = ? AND project_id = ?", (status, finding_id, project_id))
        if cursor.rowcount != 1:
            raise ValidationError("发现不属于当前项目。")


def create_remediation_task(database_path: Path, finding_id: int, root_cause: str, recommendation: str, owner: str = "", due_date: str = "") -> None:
    if not root_cause.strip() or not recommendation.strip():
        raise ValidationError("根因和修复建议不能为空。")
    try:
        with connect(database_path) as connection:
            connection.execute("INSERT INTO remediation_tasks (finding_id, root_cause, recommendation, owner, due_date) VALUES (?, ?, ?, ?, ?)", (finding_id, root_cause.strip(), recommendation.strip(), owner.strip(), due_date.strip()))
    except Exception as error:
        if "UNIQUE constraint failed" in str(error):
            raise ValidationError("该发现已存在修复任务。") from error
        raise


def list_remediation_tasks(database_path: Path, project_id: int) -> list[RemediationTask]:
    with connect(database_path) as connection:
        rows = connection.execute("SELECT remediation_tasks.finding_id, root_cause, recommendation, owner, due_date, remediation_tasks.status FROM remediation_tasks JOIN findings ON findings.id = remediation_tasks.finding_id WHERE findings.project_id = ? ORDER BY remediation_tasks.id DESC", (project_id,)).fetchall()
    return [RemediationTask(**dict(row)) for row in rows]


def update_remediation_task_status(database_path: Path, project_id: int, finding_id: int, status: str) -> None:
    if status not in {"open", "in_progress", "done"}:
        raise ValidationError("修复任务状态无效。")
    with connect(database_path) as connection:
        cursor = connection.execute(
            """
            UPDATE remediation_tasks SET status = ?
            WHERE finding_id = ? AND finding_id IN (
                SELECT id FROM findings WHERE project_id = ?
            )
            """,
            (status, finding_id, project_id),
        )
        if cursor.rowcount != 1:
            raise ValidationError("修复任务不属于当前项目。")


def record_regression_verification(
    database_path: Path, project_id: int, finding_id: int, outcome: str, detail: str
) -> None:
    if outcome not in {"passed", "failed", "skipped"}:
        raise ValidationError("回归验证结果无效。")
    normalized_detail = detail.strip()
    if not 1 <= len(normalized_detail) <= 1_000:
        raise ValidationError("回归验证摘要必须为 1 至 1000 个字符，且不得包含凭据。")
    with connect(database_path) as connection:
        finding = connection.execute(
            "SELECT 1 FROM findings WHERE id = ? AND project_id = ?", (finding_id, project_id)
        ).fetchone()
        if finding is None:
            raise ValidationError("发现不属于当前项目。")
        connection.execute(
            "INSERT INTO regression_verifications (finding_id, outcome, detail) VALUES (?, ?, ?)",
            (finding_id, outcome, normalized_detail),
        )


def list_regression_verifications(database_path: Path, project_id: int) -> list[RegressionVerification]:
    with connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT regression_verifications.finding_id, regression_verifications.outcome,
                   regression_verifications.detail, regression_verifications.created_at
            FROM regression_verifications
            JOIN findings ON findings.id = regression_verifications.finding_id
            WHERE findings.project_id = ?
            ORDER BY regression_verifications.id DESC
            """,
            (project_id,),
        ).fetchall()
    return [RegressionVerification(**dict(row)) for row in rows]


def add_role(database_path: Path, project_id: int, name: str) -> None:
    normalized_name = name.strip()
    if not 1 <= len(normalized_name) <= 80:
        raise ValidationError("角色名称必须为 1 至 80 个字符。")
    with connect(database_path) as connection:
        try:
            connection.execute("INSERT INTO roles (project_id, name) VALUES (?, ?)", (project_id, normalized_name))
        except Exception as error:
            if "UNIQUE constraint failed" in str(error):
                raise ValidationError("角色已存在。") from error
            raise


def add_resource(database_path: Path, project_id: int, name: str, method: str, endpoint: str) -> None:
    normalized_name, normalized_method, normalized_endpoint = name.strip(), method.strip().upper(), endpoint.strip()
    if not normalized_name or normalized_method not in {"GET", "POST", "PUT", "PATCH", "DELETE"} or not normalized_endpoint.startswith("/"):
        raise ValidationError("资源名称、HTTP 方法或本地接口路径无效。")
    with connect(database_path) as connection:
        try:
            connection.execute(
                "INSERT INTO protected_resources (project_id, name, method, endpoint) VALUES (?, ?, ?, ?)",
                (project_id, normalized_name, normalized_method, normalized_endpoint),
            )
        except Exception as error:
            if "UNIQUE constraint failed" in str(error):
                raise ValidationError("资源接口已存在。") from error
            raise


def list_roles(database_path: Path, project_id: int):
    with connect(database_path) as connection:
        return connection.execute("SELECT id, name FROM roles WHERE project_id = ? ORDER BY id", (project_id,)).fetchall()


def list_resources(database_path: Path, project_id: int):
    with connect(database_path) as connection:
        return connection.execute(
            "SELECT id, name, method, endpoint FROM protected_resources WHERE project_id = ? ORDER BY id", (project_id,)
        ).fetchall()


def set_permission_rule(database_path: Path, project_id: int, role_id: int, resource_id: int, expected_access: str) -> None:
    if expected_access not in {"allow", "deny"}:
        raise ValidationError("预期权限必须为 allow 或 deny。")
    with connect(database_path) as connection:
        valid = connection.execute(
            """
            SELECT (SELECT COUNT(*) FROM roles WHERE id = ? AND project_id = ?) +
                   (SELECT COUNT(*) FROM protected_resources WHERE id = ? AND project_id = ?) AS count
            """,
            (role_id, project_id, resource_id, project_id),
        ).fetchone()["count"]
        if valid != 2:
            raise ValidationError("角色或资源不属于当前项目。")
        connection.execute(
            """
            INSERT INTO permission_rules (project_id, role_id, resource_id, expected_access)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(project_id, role_id, resource_id) DO UPDATE SET expected_access = excluded.expected_access
            """,
            (project_id, role_id, resource_id, expected_access),
        )


def list_matrix_rows(database_path: Path, project_id: int) -> list[MatrixRow]:
    with connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT roles.name AS role_name, protected_resources.name AS resource_name,
                   protected_resources.method, protected_resources.endpoint, permission_rules.expected_access
            FROM permission_rules
            JOIN roles ON roles.id = permission_rules.role_id
            JOIN protected_resources ON protected_resources.id = permission_rules.resource_id
            WHERE permission_rules.project_id = ? ORDER BY roles.id, protected_resources.id
            """,
            (project_id,),
        ).fetchall()
    return [MatrixRow(**dict(row)) for row in rows]


def add_test_account_mapping(database_path: Path, project_id: int, role_id: int, account_name: str, target_url: str, authentication_type: str, credential_source: str) -> None:
    if not account_name.strip() or authentication_type not in {"cookie", "bearer"} or credential_source not in {"vault", "runtime"}:
        raise ValidationError("测试账号映射参数无效。")
    normalized_target = validate_target("local_url", target_url)
    with connect(database_path) as connection:
        role = connection.execute("SELECT 1 FROM roles WHERE id = ? AND project_id = ?", (role_id, project_id)).fetchone()
        target = connection.execute("SELECT 1 FROM project_targets WHERE project_id = ? AND target_type = 'local_url' AND value = ?", (project_id, normalized_target)).fetchone()
        if role is None or target is None:
            raise ValidationError("测试账号必须关联当前项目的角色和已登记本地 URL。")
        connection.execute("INSERT INTO test_account_mappings (project_id, role_id, account_name, target_url, authentication_type, credential_source) VALUES (?, ?, ?, ?, ?, ?)", (project_id, role_id, account_name.strip(), normalized_target, authentication_type, credential_source))


def list_test_account_mappings(database_path: Path, project_id: int) -> list[TestAccountMapping]:
    with connect(database_path) as connection:
        rows = connection.execute("SELECT roles.name AS role_name, account_name, target_url, authentication_type, credential_source FROM test_account_mappings JOIN roles ON roles.id = test_account_mappings.role_id WHERE test_account_mappings.project_id = ?", (project_id,)).fetchall()
    return [TestAccountMapping(**dict(row)) for row in rows]


def create_permission_regression_run(database_path: Path, project_id: int) -> int:
    with connect(database_path) as connection:
        cursor = connection.execute("INSERT INTO permission_regression_runs (project_id, status) VALUES (?, 'running')", (project_id,))
    return int(cursor.lastrowid)


def finish_permission_regression_run(database_path: Path, run_id: int, status: str = "completed") -> None:
    with connect(database_path) as connection:
        connection.execute("UPDATE permission_regression_runs SET status = ?, finished_at = CURRENT_TIMESTAMP WHERE id = ?", (status, run_id))


def record_permission_regression_result(
    database_path: Path, run_id: int, role_name: str, account_name: str, target_url: str,
    method: str, endpoint: str, expected_access: str, outcome: str, status_code: int | None, detail: str,
) -> None:
    with connect(database_path) as connection:
        connection.execute(
            """INSERT INTO permission_regression_results
            (run_id, role_name, account_name, target_url, method, endpoint, expected_access, outcome, status_code, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (run_id, role_name, account_name, target_url, method, endpoint, expected_access, outcome, status_code, detail[:1_000]),
        )


def list_permission_regression_results(database_path: Path, project_id: int) -> list[PermissionRegressionResult]:
    with connect(database_path) as connection:
        rows = connection.execute(
            """SELECT role_name, account_name, target_url, method, endpoint, expected_access, outcome,
                      status_code, detail, permission_regression_results.created_at
               FROM permission_regression_results
               JOIN permission_regression_runs ON permission_regression_runs.id = permission_regression_results.run_id
               WHERE permission_regression_runs.project_id = ?
               ORDER BY permission_regression_results.id DESC LIMIT 100""",
            (project_id,),
        ).fetchall()
    return [PermissionRegressionResult(**dict(row)) for row in rows]
