"""Non-network checks for the bundled local permission-regression targets."""

from __future__ import annotations

import importlib.util
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

from fastapi.testclient import TestClient

from app.permission_runner import execute_permission_request

ROOT = Path(__file__).resolve().parent.parent
TARGET_ROOT = ROOT / "test_targets"


def _load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_fastapi_target_rejects_cross_account_access_and_accepts_cookie_login(monkeypatch) -> None:
    target = _load_module("local_fastapi_target", TARGET_ROOT / "fastapi_target" / "app.py")
    user_a_token = secrets.token_urlsafe(24)
    user_b_token = secrets.token_urlsafe(24)
    admin_token = secrets.token_urlsafe(24)
    monkeypatch.setenv("FASTAPI_TARGET_USER_A_TOKEN", user_a_token)
    monkeypatch.setenv("FASTAPI_TARGET_USER_B_TOKEN", user_b_token)
    monkeypatch.setenv("FASTAPI_TARGET_ADMIN_TOKEN", admin_token)

    with TestClient(target.app) as client:
        assert client.get("/api/profiles/user-a").status_code == 401
        cross_account_response = client.get(
            "/api/profiles/user-a",
            headers={"Authorization": f"Bearer {user_b_token}"},
        )
        assert cross_account_response.status_code == 403
        login = client.post("/test-login", headers={"Authorization": f"Bearer {user_a_token}"})
        assert login.status_code == 204
        assert client.get("/api/profiles/user-a").status_code == 200
        assert client.get("/api/admin/stats").status_code == 403
        admin_response = client.get(
            "/api/admin/stats",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert admin_response.status_code == 200


def test_node_target_is_pinned_to_loopback_and_has_no_runtime_dependencies() -> None:
    source = (TARGET_ROOT / "node_target" / "server.mjs").read_text(encoding="utf-8")
    manifest = (TARGET_ROOT / "node_target" / "package.json").read_text(encoding="utf-8")
    assert "const host = '127.0.0.1';" in source
    assert "server.listen(port, host" in source
    assert '"dependencies"' not in manifest


def test_registration_creates_only_non_sensitive_runtime_account_mappings(tmp_path: Path) -> None:
    registration = _load_module("local_target_registration", TARGET_ROOT / "register_targets.py")
    database_path = tmp_path / "workbench.sqlite3"

    project_id = registration.register_targets(database_path)
    registration.register_targets(database_path)

    from app.projects import list_test_account_mappings

    mappings = list_test_account_mappings(database_path, project_id)
    assert len(mappings) == 6
    assert {mapping.credential_source for mapping in mappings} == {"runtime"}
    assert all("token" not in mapping.account_name.lower() for mapping in mappings)


def _port_is_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        return connection.connect_ex(("127.0.0.1", port)) != 0


def _wait_for_health(url: str) -> None:
    for _ in range(50):
        try:
            with urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"Local target did not become healthy: {url}")


def test_bundled_targets_complete_real_local_permission_matrix_regression() -> None:
    """Exercise the approved loopback targets with ephemeral, non-persisted credentials."""

    assert _port_is_available(8101), "Port 8101 is occupied; target was not started."
    assert _port_is_available(8102), "Port 8102 is occupied; target was not started."
    node = shutil.which("node")
    assert node is not None, "Node.js is required for the bundled local Node target."

    environment = os.environ.copy()
    for prefix in ("FASTAPI_TARGET", "NODE_TARGET"):
        environment[f"{prefix}_USER_A_TOKEN"] = secrets.token_urlsafe(24)
        environment[f"{prefix}_USER_B_TOKEN"] = secrets.token_urlsafe(24)
        environment[f"{prefix}_ADMIN_TOKEN"] = secrets.token_urlsafe(24)

    fastapi_process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app:app",
            "--app-dir",
            str(TARGET_ROOT / "fastapi_target"),
            "--host",
            "127.0.0.1",
            "--port",
            "8101",
        ],
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    node_process = subprocess.Popen(
        [node, str(TARGET_ROOT / "node_target" / "server.mjs")],
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_health("http://127.0.0.1:8101/health")
        _wait_for_health("http://127.0.0.1:8102/health")
        checks = []
        for base_url, authentication_type, prefix in (
            ("http://127.0.0.1:8101", "bearer", "FASTAPI_TARGET"),
            ("http://127.0.0.1:8102", "cookie", "NODE_TARGET"),
        ):
            credentials = {
                "user-a": environment[f"{prefix}_USER_A_TOKEN"],
                "user-b": environment[f"{prefix}_USER_B_TOKEN"],
                "admin": environment[f"{prefix}_ADMIN_TOKEN"],
            }
            matrix = (
                ("guest", None, "GET", "/api/profiles/user-a", "deny"),
                ("user-a", credentials["user-a"], "GET", "/api/profiles/user-a", "allow"),
                ("user-b", credentials["user-b"], "GET", "/api/profiles/user-a", "deny"),
                ("admin", credentials["admin"], "GET", "/api/profiles/user-a", "allow"),
                ("guest", None, "POST", "/api/orders/user-a", "deny"),
                ("user-a", credentials["user-a"], "POST", "/api/orders/user-a", "allow"),
                ("user-b", credentials["user-b"], "POST", "/api/orders/user-a", "deny"),
                ("admin", credentials["admin"], "POST", "/api/orders/user-a", "allow"),
                ("guest", None, "GET", "/api/admin/stats", "deny"),
                ("user-a", credentials["user-a"], "GET", "/api/admin/stats", "deny"),
                ("user-b", credentials["user-b"], "GET", "/api/admin/stats", "deny"),
                ("admin", credentials["admin"], "GET", "/api/admin/stats", "allow"),
            )
            checks.extend(
                execute_permission_request(base_url, endpoint, method, expected, authentication_type, credential)
                for _, credential, method, endpoint, expected in matrix
            )
        assert len(checks) == 24
        assert all(check.outcome == "passed" for check in checks)
    finally:
        for process in (fastapi_process, node_process):
            process.terminate()
            process.wait(timeout=10)
