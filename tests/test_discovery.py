"""Tests for bounded, offline manifest discovery in registered code directories."""

from __future__ import annotations

from pathlib import Path

from app import discovery
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


def test_runtime_discovery_suggests_only_loopback_listeners_and_docker_names(monkeypatch) -> None:
    outputs = {
        ("netstat", "-ano", "-p", "tcp"): "  TCP    127.0.0.1:8101      0.0.0.0:0      LISTENING\n  TCP    10.0.0.5:9000       0.0.0.0:0      LISTENING\n",
        ("docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}"): "local-target\texample/target:latest\t127.0.0.1:8102->8102/tcp\n",
    }

    class Result:
        returncode = 0

        def __init__(self, stdout: str):
            self.stdout = stdout

    def fake_run(command, **_kwargs):
        return Result(outputs[tuple(command)])

    monkeypatch.setattr(discovery.subprocess, "run", fake_run)
    monkeypatch.setattr(discovery.shutil, "which", lambda _name: "docker")

    result = discovery.discover_runtime_assets()

    assert ("local_url", "http://127.0.0.1:8101", "检测到 127.0.0.1 TCP 监听；尚未登记或请求。") in result.candidates
    assert not any("10.0.0.5" in candidate[1] for candidate in result.candidates)
    assert ("docker_service", "local-target", "镜像：example/target:latest；端口：127.0.0.1:8102->8102/tcp。") in result.candidates


def test_runtime_discovery_records_unavailable_sources_without_probing(monkeypatch) -> None:
    def unavailable(*_args, **_kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(discovery.subprocess, "run", unavailable)
    monkeypatch.setattr(discovery.shutil, "which", lambda _name: None)

    result = discovery.discover_runtime_assets()

    assert result.candidates[0][0] == "code_directory"
    assert any("本机监听发现已跳过" in detail for detail in result.skipped)
    assert any("Docker 容器发现已跳过" in detail for detail in result.skipped)
