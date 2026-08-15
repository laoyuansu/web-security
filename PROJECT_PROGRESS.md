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

## 小项目：HTTP 安全基线回归

状态：已验证，待提交。

### 监测目标与实际证据

| 目标 | 可观察通过条件 | 实际证据 |
| --- | --- | --- |
| 已登记目标请求 | 仅对登记的回环 URL 发起 HTTP 请求 | `tests/test_checks.py::test_http_baseline_requests_only_a_registered_loopback_service` 在临时 `127.0.0.1` 服务上通过。 |
| 安全响应头 | 三项基线响应头均存在时记录通过且不创建 HTTP 基线发现 | 同一测试通过。 |
| 回归 | 全部测试、静态检查和差异检查通过 | `.\.venv\Scripts\python.exe -m pytest`：30 passed；Ruff 与 `git diff --check`：通过。 |

## 大项目终验

结论：通过，可交工。

| PRD 验收标准 | 结果与证据 |
| --- | --- |
| 项目与资产登记/发现 | 通过：项目、资产手动登记和已登记目录导入由路由与发现测试覆盖；受限发现只展示当前项目、回环监听和 Docker 名称候选，仍须手动登记。 |
| 五类检查与跳过记录 | 通过：代码/配置/Git 历史、依赖、配置、HTTP 基线和权限矩阵均有自动化证据；未登记 HTTP URL 与不可用 Docker 均记录为跳过。 |
| Cookie 与 Bearer 权限矩阵 | 通过：两套本机靶场实际运行，24 条 Cookie/Bearer 规则均通过；违规会记录高优先级待确认发现。 |
| 凭据隔离 | 通过：SQLite 仅保存凭据来源和账号映射；报告、备份、日志式证据均不保存凭据，测试覆盖敏感备份拒绝。 |
| 发现到修复到回归关闭 | 通过：自动化路由测试确认未通过回归不能关闭发现，通过后才可关闭。 |
| 报告、备份与删除 | 通过：Markdown、脱敏 JSON 导入/导出、重复导入命名及精确项目名删除均由测试覆盖。 |
| 默认离线 | 通过：依赖检查仅做本地版本基线；本轮未查询漏洞库或上传任何数据。 |
| 自动化质量门 | 通过：`pytest` 30 passed、`ruff check .` 通过、`git diff --check` 通过、`git fsck --no-dangling` 无输出。 |

### 未验证项与残余风险

- Docker CLI 存在但 `docker ps` 未成功完成，因此没有实际容器发现或 Compose 启动证据；应用会显式记录跳过，不会将其视为已发现或已通过。
- 未以 Edge 手工执行浏览器交互；TestClient 覆盖了页面路由、登录、CSRF 和表单流程。
- 未实际读写 Windows 凭据库；自动化覆盖凭据不落盘、运行时凭据跳过及 Keyring 错误降级。
- Git 历史中有 2 个测试形态的 OpenAI 风格字符串命中，临时终验记录已分诊为误报；没有匹配值被输出或写入报告。
