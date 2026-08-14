$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
& (Join-Path $projectRoot '.venv\Scripts\python.exe') -m uvicorn app:app --app-dir $PSScriptRoot --host 127.0.0.1 --port 8101
