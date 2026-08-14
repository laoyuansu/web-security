# 本地权限回归靶场

本目录包含两个仅用于本机权限回归的样例服务：一个 FastAPI 靶场与一个不依赖第三方包的 Node.js 靶场。它们不是生产服务，也不得绑定到公网或局域网地址。

## 安全约束

- 两个靶场只监听 `127.0.0.1`，默认端口分别为 `8101` 与 `8102`。
- 受保护接口仅接受运行时环境变量中提供的专用测试 Token；Token、Cookie 与密码不写入项目文件、SQLite、日志或 Git。
- 受保护接口覆盖 Bearer Token 与通过 `/test-login` 签发的 HttpOnly Cookie 两种认证方式。
- `guest`、`user-a`、`user-b` 与 `admin` 是测试身份名称，不是可复用的自查台管理员账号。

## 注册而不保存凭据

在自查台已启动、并已由管理员登录后，可在项目根目录运行以下命令，将两个靶场的代码目录、localhost URL、资产、权限矩阵与“运行时凭据”账号映射写入本机 SQLite：

```powershell
.\.venv\Scripts\python .\test_targets\register_targets.py
```

该命令会修改本机 `data\workbench.sqlite3`，不会写入或显示任何凭据；重复执行是幂等的。执行前应确认这两个 URL 没有被其他程序占用或登记给其他项目。

## 启动与凭据

启动前，必须由安全的本机流程在当前 PowerShell 会话中提供下列环境变量，且不能把值复制到脚本、终端记录或版本库中：

- `FASTAPI_TARGET_USER_A_TOKEN`
- `FASTAPI_TARGET_USER_B_TOKEN`
- `FASTAPI_TARGET_ADMIN_TOKEN`
- `NODE_TARGET_USER_A_TOKEN`
- `NODE_TARGET_USER_B_TOKEN`
- `NODE_TARGET_ADMIN_TOKEN`

然后分别使用各靶场目录下的 `start.ps1` 启动。测试客户端可将 Token 放入 `Authorization: Bearer ...`，或先调用 `POST /test-login` 获取仅限当前本地会话的 Cookie。未配置 Token 时，所有受保护请求都会被拒绝。

## 权限矩阵

| 资源 | guest | user-a | user-b | admin |
| --- | --- | --- | --- | --- |
| `GET /api/profiles/user-a` | 拒绝 | 允许 | 拒绝 | 允许 |
| `POST /api/orders/user-a` | 拒绝 | 允许 | 拒绝 | 允许 |
| `GET /api/admin/stats` | 拒绝 | 拒绝 | 拒绝 | 允许 |

每个靶场均提供 `GET /health` 用于确认服务可达；该端点不涉及凭据或业务数据。
