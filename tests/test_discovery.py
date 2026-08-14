"""Tests for bounded, offline manifest discovery in registered code directories."""

from __future__ import annotations

from pathlib import Path

from app.database import initialize_database
from app.discovery import import_registered_project_files
from app.projects import add_target, create_project, list_assets, list_import_records


def test_imports_known_manifest_files_from_registered_directory(tmp_path: Path) -> None:
    database_path = tmp_path / "workbench.sqlite3"
    source_directory = tmp_path / "authorized-project"
    source_directory.mkdir()
    (source_directory / "requirements.txt").write_text("fastapi==0.141.1\n", encoding="utf-8")
    (source_directory / "package.json").write_text(
        '{"dependencies":{"vite":"1.0.0"}}', encoding="utf-8"
    )
    (source_directory / "compose.yaml").write_text("services:\n  app:\n    image: example/app\n", encoding="utf-8")
    (source_directory / "openapi.yaml").write_text(
        "openapi: 3.0.0\ninfo:\n  title: Sample API\npaths:\n  /profile:\n    get: {}\n",
        encoding="utf-8",
    )
    initialize_database(database_path)
    project = create_project(database_path, "导入项目", "")
    add_target(database_path, project.id, "code_directory", str(source_directory))

    import_registered_project_files(database_path, project.id)

    assets = {(asset.asset_type, asset.name) for asset in list_assets(database_path, project.id)}
    records = list_import_records(database_path, project.id)
    assert ("dependency", "fastapi") in assets
    assert ("dependency", "vite") in assets
    assert ("docker_service", "app") in assets
    assert ("api", "GET /profile") in assets
    assert {record.source_kind for record in records} == {"requirements", "package_json", "docker_compose", "openapi"}


def test_records_skipped_imports_when_no_directory_is_registered(tmp_path: Path) -> None:
    database_path = tmp_path / "workbench.sqlite3"
    initialize_database(database_path)
    project = create_project(database_path, "空范围", "")

    import_registered_project_files(database_path, project.id)

    records = list_import_records(database_path, project.id)
    assert len(records) == 4
    assert {record.outcome for record in records} == {"skipped"}
    assert {record.detail for record in records} == {"未登记代码目录。"}
