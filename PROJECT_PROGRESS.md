# 项目进度与验证证据

## 小项目：发现闭环、脱敏备份与权限矩阵回归

状态：已验证，待提交。

### 监测目标

| 目标 | 可观察通过条件 | 实际证据 |
| --- | --- | --- |
| 发现闭环 | 未通过回归的发现不能关闭；通过回归后可以关闭 | `tests/test_projects.py::test_findings_page_requires_regression_before_closing_a_finding` 通过。 |
| 脱敏数据与删除保护 | 含敏感字段的备份被拒绝；删除要求精确项目名称 | `tests/test_checks.py` 与 `tests/test_projects.py::test_report_page_imports_only_a_redacted_json_backup` 通过。 |
| 权限矩阵边界 | 仅登记的本地 URL 可绑定账号；运行时凭据不保存 | `tests/test_matrix.py`、`tests/test_permission_runner.py` 与 `tests/test_local_targets.py` 通过。 |
| 页面回归 | 角色、资源、规则可保存；无测试账号时回归安全跳过 | `tests/test_projects.py::test_matrix_routes_save_rules_and_skip_unmapped_accounts` 通过。 |

### 实际验证

- 时间：2026-08-15（Asia/Shanghai）。
- `.\.venv\Scripts\python.exe -m pytest`：25 passed，1 条第三方弃用警告。
- `.\.venv\Scripts\python.exe -m pytest tests/test_local_targets.py -v`：4 passed；仅启动并访问本仓库的 `127.0.0.1:8101` 与 `127.0.0.1:8102` 靶场，24 条权限规则全部符合预期。
- `.\.venv\Scripts\python.exe -m ruff check .`：通过。
- `git diff --check`：通过。
- 已检查 Git 跟踪的 `.env` 文件和常见凭据赋值模式；未发现已跟踪的实际凭据。命中项仅为文档占位符、变量名、CSRF 逻辑和测试运行时值。

### 未验证项与残余风险

- 未实际访问 Windows 凭据库；自动化验证覆盖运行时凭据跳过和凭据不落盘边界。
- 未运行 Docker Compose 或以 Edge 手工浏览；相关行为由 TestClient、静态配置检查和本机靶场测试覆盖。
- 未进行联网漏洞库查询，符合默认离线要求。

## 小项目：受限资产发现

状态：已验证，待提交。

### 监测目标与实际证据

| 目标 | 可观察通过条件 | 实际证据 |
| --- | --- | --- |
| 本机服务边界 | 仅列出 `127.0.0.1`/`localhost` 监听项，不探测或请求服务 | `tests/test_discovery.py` 验证局域网地址被排除；真实发现返回 1 个候选（当前自查台目录），未请求任何 URL。 |
| Docker 降级 | 固定只读 `docker ps` 失败时保留跳过原因 | 单元测试覆盖不可用命令；真实运行中 Docker 命令未成功完成，结果标为跳过。 |
| 防误操作 | 候选仅展示，仍须手动登记后才可导入或检查 | `tests/test_projects.py::test_runtime_discovery_shows_candidates_without_registering_them` 通过。 |

### 实际验证

- `.\.venv\Scripts\python.exe -c "from app.discovery import discover_runtime_assets; ..."`：候选数为 1；跳过数为 1（Docker 发现命令未成功完成）。
- `.\.venv\Scripts\python.exe -m pytest`：28 passed，1 条第三方弃用警告。
- `.\.venv\Scripts\python.exe -m ruff check .` 与 `git diff --check`：通过。

## 小项目：Git 历史密钥自查

状态：已验证，待提交。

### 监测目标与实际证据

| 目标 | 可观察通过条件 | 实际证据 |
| --- | --- | --- |
| Git 历史覆盖 | 已登记 Git 目录的完整历史按签名检查 | `tests/test_checks.py::test_checks_detect_redacted_secret_signatures_in_authorized_git_history` 通过。 |
| 脱敏 | 发现只包含类型和提交哈希，不包含匹配值 | 同一测试确认测试形态不出现在证据中。 |
| 降级 | 无 Git 或失败时保留跳过原因而不中断其他检查 | 实现与既有无目标跳过测试覆盖该路径。 |

### 实际验证

- 使用 `.pytest_cache/final-audit.sqlite3` 的临时项目对当前工作树运行离线检查：`secret_leak`、`dependency`、`configuration` 为 passed；未登记 URL 的 `http_baseline` 为 skipped。
- 当前 Git 历史检测到 2 个测试形态签名；均在临时终验记录中标为 `false_positive`，未保存匹配值。
- `.\.venv\Scripts\python.exe -m pytest`：29 passed，1 条第三方弃用警告；`.\.venv\Scripts\python.exe -m ruff check .` 与 `git diff --check`：通过。
