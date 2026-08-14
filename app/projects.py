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
