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
