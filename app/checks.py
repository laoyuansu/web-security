"""Bounded, offline-first checks for project-authorized local targets."""

from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from app.projects import (
    create_check_run,
    finish_check_run,
    list_code_directories,
    list_targets,
    record_check_result,
    record_finding,
)

MAX_SOURCE_FILE_BYTES = 1_000_000
IGNORED_DIRECTORY_NAMES = {".git", ".venv", "node_modules", "dist", "build", "__pycache__"}
SECRET_SIGNATURES = {
    "OpenAI-like key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "GitHub token": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b", re.IGNORECASE),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}


def _source_files(directory: Path):
    for path in directory.rglob("*"):
        if any(part in IGNORED_DIRECTORY_NAMES for part in path.parts):
            continue
        if path.is_file() and path.stat().st_size <= MAX_SOURCE_FILE_BYTES:
            yield path


def _add_finding(database_path: Path, project_id: int, run_id: int, **finding) -> None:
    record_finding(database_path, project_id, run_id, **finding)


def _run_secret_check(database_path: Path, project_id: int, run_id: int, directories: list[Path]) -> None:
    if not directories:
        record_check_result(database_path, run_id, "secret_leak", "skipped", "未登记代码目录。")
        return
    hits = 0
    for directory in directories:
        for path in _source_files(directory):
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            for number, line in enumerate(lines, start=1):
                for label, pattern in SECRET_SIGNATURES.items():
                    if pattern.search(line):
                        hits += 1
                        _add_finding(
                            database_path,
                            project_id,
                            run_id,
                            title="疑似密钥泄露",
                            module=str(path.relative_to(directory)),
                            finding_type="secret_leak",
                            severity="high",
                            evidence=f"{label} 命中于第 {number} 行；匹配值已脱敏。",
                            expected="代码与配置中不包含真实密钥。",
                            actual="检测到疑似密钥签名。",
                        )
    record_check_result(database_path, run_id, "secret_leak", "passed", f"已检查，发现 {hits} 项待确认结果。")


def _run_dependency_check(database_path: Path, project_id: int, run_id: int, directories: list[Path]) -> None:
    if not directories:
        record_check_result(database_path, run_id, "dependency", "skipped", "未登记代码目录。")
        return
    findings = 0
    for directory in directories:
        requirements = directory / "requirements.txt"
        if requirements.is_file():
            for number, line in enumerate(requirements.read_text(encoding="utf-8").splitlines(), start=1):
                value = line.split("#", maxsplit=1)[0].strip()
                if value and not value.startswith("-") and "==" not in value:
                    findings += 1
                    _add_finding(
                        database_path, project_id, run_id, title="Python 依赖未精确固定", module="requirements.txt",
                        finding_type="dependency", severity="low", evidence=f"第 {number} 行未使用 == 固定版本。",
                        expected="可复现的依赖版本。", actual="依赖版本可能随安装时间变化。"
                    )
        package_json = directory / "package.json"
        if package_json.is_file():
            try:
                data = json.loads(package_json.read_text(encoding="utf-8"))
                for section in ("dependencies", "devDependencies"):
                    for name, version in data.get(section, {}).items():
                        if isinstance(version, str) and version in {"*", "latest"}:
                            findings += 1
                            _add_finding(
                                database_path, project_id, run_id, title="Node 依赖使用浮动版本", module="package.json",
                                finding_type="dependency", severity="low", evidence=f"{name} 使用 {version}。",
                                expected="可复现的依赖版本。", actual="依赖版本可能随安装时间变化。"
                            )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                pass
    record_check_result(database_path, run_id, "dependency", "passed", f"本地依赖基线检查完成，发现 {findings} 项待确认结果。")


def _run_configuration_check(database_path: Path, project_id: int, run_id: int, directories: list[Path]) -> None:
    if not directories:
        record_check_result(database_path, run_id, "configuration", "skipped", "未登记代码目录。")
        return
    findings = 0
    for directory in directories:
        environment_file = directory / ".env"
        if environment_file.is_file():
            tracked = subprocess.run(
                ["git", "ls-files", "--error-unmatch", ".env"],
                cwd=directory,
                capture_output=True,
                text=True,
                check=False,
            ).returncode == 0
            if tracked:
                findings += 1
                _add_finding(
                    database_path, project_id, run_id, title=".env 文件被 Git 跟踪", module=".env",
                    finding_type="configuration", severity="high", evidence="git ls-files 显示 .env 已被跟踪。",
                    expected="敏感环境文件不进入版本控制。", actual=".env 已被版本控制。"
                )
        for filename in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            compose_file = directory / filename
            if compose_file.is_file() and re.search(r"(?im)^\s*privileged\s*:\s*true\s*$", compose_file.read_text(encoding="utf-8")):
                findings += 1
                _add_finding(
                    database_path, project_id, run_id, title="Docker 服务使用 privileged", module=filename,
                    finding_type="configuration", severity="high", evidence="Compose 文件包含 privileged: true。",
                    expected="容器使用最小权限。", actual="容器被授予特权模式。"
                )
    record_check_result(database_path, run_id, "configuration", "passed", f"基础配置检查完成，发现 {findings} 项待确认结果。")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _run_http_check(database_path: Path, project_id: int, run_id: int) -> None:
    urls = [target.value for target in list_targets(database_path, project_id) if target.target_type == "local_url"]
    if not urls:
        record_check_result(database_path, run_id, "http_baseline", "skipped", "未登记本地 URL。")
        return
    opener = urllib.request.build_opener(_NoRedirect())
    findings = 0
    for url in urls:
        try:
            with opener.open(url, timeout=5) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
        except (urllib.error.URLError, OSError) as error:
            record_check_result(database_path, run_id, "http_baseline", "error", f"{url} 不可访问：{type(error).__name__}。")
            continue
        for header in ("x-content-type-options", "x-frame-options", "content-security-policy"):
            if header not in headers:
                findings += 1
                _add_finding(
                    database_path, project_id, run_id, title="缺少 HTTP 安全响应头", module=url,
                    finding_type="http_baseline", severity="low", evidence=f"未返回 {header}。",
                    expected="本地 Web 服务应提供适当的安全响应头。", actual=f"缺少 {header}。"
                )
    record_check_result(database_path, run_id, "http_baseline", "passed", f"HTTP 基线检查完成，发现 {findings} 项待确认结果。")


def run_project_checks(database_path: Path, project_id: int) -> None:
    """Run only offline checks plus HTTP requests to registered local URLs."""

    run_id = create_check_run(database_path, project_id)
    try:
        directories = list_code_directories(database_path, project_id)
        _run_secret_check(database_path, project_id, run_id, directories)
        _run_dependency_check(database_path, project_id, run_id, directories)
        _run_configuration_check(database_path, project_id, run_id, directories)
        _run_http_check(database_path, project_id, run_id)
    except Exception:
        finish_check_run(database_path, run_id, "failed")
        raise
    finish_check_run(database_path, run_id)
