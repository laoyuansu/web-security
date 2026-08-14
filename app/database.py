"""SQLite storage for local project and asset metadata."""

from __future__ import annotations

import sqlite3
from pathlib import Path


def connect(database_path: Path) -> sqlite3.Connection:
    """Open a connection with foreign-key enforcement enabled."""

    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(database_path: Path) -> None:
    """Create the initial local-only schema without storing credentials."""

    database_path.parent.mkdir(parents=True, exist_ok=True)
    with connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS project_targets (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                target_type TEXT NOT NULL CHECK (target_type IN (
                    'code_directory', 'local_url', 'docker_address'
                )),
                value TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(project_id, target_type, value)
            );

            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                asset_type TEXT NOT NULL CHECK (asset_type IN (
                    'page', 'api', 'data_type', 'dependency', 'docker_service'
                )),
                name TEXT NOT NULL,
                value TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(project_id, asset_type, name)
            );

            CREATE TABLE IF NOT EXISTS import_records (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                source_kind TEXT NOT NULL CHECK (source_kind IN (
                    'openapi', 'requirements', 'package_json', 'docker_compose'
                )),
                source_path TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK (outcome IN ('imported', 'skipped', 'error')),
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS check_runs (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
                started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                finished_at TEXT
            );

            CREATE TABLE IF NOT EXISTS check_results (
                id INTEGER PRIMARY KEY,
                check_run_id INTEGER NOT NULL REFERENCES check_runs(id) ON DELETE CASCADE,
                check_type TEXT NOT NULL CHECK (check_type IN (
                    'secret_leak', 'dependency', 'configuration', 'http_baseline'
                )),
                outcome TEXT NOT NULL CHECK (outcome IN ('passed', 'skipped', 'error')),
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                check_run_id INTEGER NOT NULL REFERENCES check_runs(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                module TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
                evidence TEXT NOT NULL,
                expected TEXT NOT NULL,
                actual TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
                    'pending', 'confirmed', 'false_positive', 'fixed'
                )),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS remediation_tasks (
                id INTEGER PRIMARY KEY,
                finding_id INTEGER NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
                root_cause TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                owner TEXT NOT NULL DEFAULT '',
                due_date TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'done')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                UNIQUE(project_id, name)
            );

            CREATE TABLE IF NOT EXISTS protected_resources (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                method TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                UNIQUE(project_id, method, endpoint)
            );

            CREATE TABLE IF NOT EXISTS permission_rules (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
                resource_id INTEGER NOT NULL REFERENCES protected_resources(id) ON DELETE CASCADE,
                expected_access TEXT NOT NULL CHECK (expected_access IN ('allow', 'deny')),
                UNIQUE(project_id, role_id, resource_id)
            );

            CREATE TABLE IF NOT EXISTS test_account_mappings (
                id INTEGER PRIMARY KEY,
                project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
                account_name TEXT NOT NULL,
                authentication_type TEXT NOT NULL CHECK (authentication_type IN ('cookie', 'bearer')),
                credential_source TEXT NOT NULL CHECK (credential_source IN ('vault', 'runtime')),
                UNIQUE(project_id, role_id, account_name)
            );
            """
        )
