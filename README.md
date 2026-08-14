# 本地 Web 安全自查与修复台

这是一个仅面向已登记本机项目和本地靶场的安全自查与修复工作台。它不会扫描公网、局域网其他设备或未登记目标。

## 安全启动要求

服务应仅绑定 `127.0.0.1`。管理员密码和会话密钥必须通过当前 PowerShell 会话或受信任的本机密钥管理流程提供，不能写入项目文件、Git、日志或报告。

```powershell
$env:APP_ADMIN_USERNAME = 'local-admin'
$env:APP_ADMIN_PASSWORD = '<至少 12 个字符的独立密码>'
$env:APP_SESSION_SECRET = '<至少 32 个字符的随机会话密钥>'
.\.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

然后在 Edge 中访问 `http://127.0.0.1:8000`。

## 本地验证

```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m ruff check .
```

## Docker

Docker 仅将容器端口映射至主机 `127.0.0.1`。启动前在当前 PowerShell 会话设置 `APP_ADMIN_PASSWORD` 和 `APP_SESSION_SECRET`，再执行：

```powershell
docker compose up --build
```

该命令会构建镜像并启动本地容器，属于有副作用操作，需在执行前确认。
