"""Bounded, offline asset discovery inside already-authorized code directories."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml

from app.projects import (
    ValidationError,
    add_asset,
    list_assets,
    list_code_directories,
    record_import,
)

MAX_IMPORT_FILE_BYTES = 1_000_000
IMPORT_FILES = {
    "requirements": ("requirements.txt",),
    "package_json": ("package.json",),
    "docker_compose": ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"),
    "openapi": ("openapi.json", "openapi.yaml", "openapi.yml"),
}
LISTENING_ADDRESS = re.compile(
    r"^\s*TCP\s+(?P<host>127\.0\.0\.1|localhost):(?P<port>\d+)\s+\S+\s+LISTENING\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RuntimeDiscovery:
    """Candidate local assets plus reasons for any safely skipped discovery source."""

    candidates: tuple[tuple[str, str, str], ...]
    skipped: tuple[str, ...]


def _completed_output(command: list[str]) -> tuple[str | None, str | None]:
    """Run a fixed, read-only local command without exposing its error output to the UI."""

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=3, check=False)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None, "命令不可用、被拒绝或超时。"
    if result.returncode != 0:
        return None, "命令未成功完成。"
    return result.stdout, None


def _listening_local_urls(netstat_output: str) -> list[tuple[str, str, str]]:
    urls: set[str] = set()
    for line in netstat_output.splitlines():
        match = LISTENING_ADDRESS.match(line)
        if match is not None:
            urls.add(f"http://127.0.0.1:{match.group('port')}")
    return [("local_url", url, "检测到 127.0.0.1 TCP 监听；尚未登记或请求。") for url in sorted(urls)]


def _docker_candidates(docker_output: str) -> list[tuple[str, str, str]]:
    candidates = []
    for line in docker_output.splitlines():
        name, separator, remainder = line.partition("\t")
        image, _, ports = remainder.partition("\t")
        if separator and name.strip():
            candidates.append(("docker_service", name.strip(), f"镜像：{image.strip() or '未知'}；端口：{ports.strip() or '未公开'}。"))
    return candidates


def discover_runtime_assets() -> RuntimeDiscovery:
    """Suggest only self, loopback listeners, and Docker names; never register or probe a target."""

    candidates = [("code_directory", str(Path(__file__).resolve().parent.parent), "当前自查台项目目录。")]
    skipped = []
    netstat_output, netstat_error = _completed_output(["netstat", "-ano", "-p", "tcp"])
    if netstat_output is None:
        skipped.append(f"本机监听发现已跳过：{netstat_error}")
    else:
        candidates.extend(_listening_local_urls(netstat_output))

    if shutil.which("docker") is None:
        skipped.append("Docker 容器发现已跳过：未检测到 Docker CLI。")
    else:
        docker_output, docker_error = _completed_output(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}"]
        )
        if docker_output is None:
            skipped.append(f"Docker 容器发现已跳过：{docker_error}")
        else:
            candidates.extend(_docker_candidates(docker_output))
    return RuntimeDiscovery(tuple(candidates), tuple(skipped))


def _read_text(path: Path) -> str:
    if path.stat().st_size > MAX_IMPORT_FILE_BYTES:
        raise ValueError("文件超过 1 MB 导入限制。")
    return path.read_text(encoding="utf-8")


def _add_discovered_assets(database_path: Path, project_id: int, assets: Iterable[tuple[str, str, str]]) -> int:
    existing_assets = {(asset.asset_type, asset.name) for asset in list_assets(database_path, project_id)}
    added_count = 0
    for asset_type, name, value in assets:
        key = (asset_type, name)
        if key in existing_assets:
            continue
        try:
            add_asset(database_path, project_id, asset_type, name, value)
        except ValidationError:
            continue
        existing_assets.add(key)
        added_count += 1
    return added_count


def _requirements_assets(source_text: str) -> list[tuple[str, str, str]]:
    assets = []
    for raw_line in source_text.splitlines():
        requirement = raw_line.split("#", maxsplit=1)[0].strip()
        if not requirement or requirement.startswith(("-", "git+", "http://", "https://")):
            continue
        name = requirement
        for separator in ("===", "==", ">=", "<=", "~=", ">", "<", "!=", ";", "["):
            name = name.split(separator, maxsplit=1)[0]
        name = name.strip()
        if name:
            assets.append(("dependency", name, requirement))
    return assets


def _package_assets(source_text: str) -> list[tuple[str, str, str]]:
    document = json.loads(source_text)
    if not isinstance(document, dict):
        raise TypeError("package.json 根节点必须是对象。")
    assets = []
    for section in ("dependencies", "devDependencies"):
        dependencies = document.get(section, {})
        if not isinstance(dependencies, dict):
            continue
        for name, version in dependencies.items():
            if isinstance(name, str) and isinstance(version, str):
                assets.append(("dependency", name, f"{section}: {version}"))
    return assets


def _compose_assets(source_text: str) -> list[tuple[str, str, str]]:
    document = yaml.safe_load(source_text)
    if not isinstance(document, dict):
        raise TypeError("Compose 文件根节点必须是对象。")
    services = document.get("services", {})
    if not isinstance(services, dict):
        raise TypeError("Compose 文件缺少 services 对象。")
    return [("docker_service", name, "从 Compose 文件导入") for name in services if isinstance(name, str)]


def _openapi_assets(source_text: str) -> list[tuple[str, str, str]]:
    document = json.loads(source_text) if source_text.lstrip().startswith("{") else yaml.safe_load(source_text)
    if not isinstance(document, dict):
        raise TypeError("OpenAPI 文件根节点必须是对象。")
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        raise TypeError("OpenAPI 文件缺少 paths 对象。")
    title = document.get("info", {}).get("title", "OpenAPI") if isinstance(document.get("info"), dict) else "OpenAPI"
    assets = []
    for path, operations in paths.items():
        if not isinstance(path, str) or not isinstance(operations, dict):
            continue
        for method in operations:
            if isinstance(method, str) and method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"}:
                assets.append(("api", f"{method.upper()} {path}", str(title)))
    return assets


def _import_source(
    database_path: Path, project_id: int, source_kind: str, source_path: Path, parser
) -> None:
    try:
        added_count = _add_discovered_assets(database_path, project_id, parser(_read_text(source_path)))
    except (OSError, UnicodeDecodeError, ValueError, TypeError, yaml.YAMLError) as error:
        record_import(database_path, project_id, source_kind, str(source_path), "error", str(error))
        return
    record_import(
        database_path,
        project_id,
        source_kind,
        str(source_path),
        "imported",
        f"已新增 {added_count} 项资产；重复项已跳过。",
    )


def import_registered_project_files(database_path: Path, project_id: int) -> None:
    """Import known manifests only from code directories registered to this project."""

    parser_by_kind = {
        "requirements": _requirements_assets,
        "package_json": _package_assets,
        "docker_compose": _compose_assets,
        "openapi": _openapi_assets,
    }
    directories = list_code_directories(database_path, project_id)
    if not directories:
        for source_kind in IMPORT_FILES:
            record_import(database_path, project_id, source_kind, "", "skipped", "未登记代码目录。")
        return

    for directory in directories:
        for source_kind, filenames in IMPORT_FILES.items():
            source_path = next((directory / name for name in filenames if (directory / name).is_file()), None)
            if source_path is None:
                record_import(
                    database_path,
                    project_id,
                    source_kind,
                    str(directory),
                    "skipped",
                    "未找到对应导入文件。",
                )
                continue
            _import_source(database_path, project_id, source_kind, source_path, parser_by_kind[source_kind])
