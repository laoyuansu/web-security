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
            """
        )
