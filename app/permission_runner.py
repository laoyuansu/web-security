"""Permission-regression request builder with fail-closed credential handling."""

from __future__ import annotations

from dataclasses import dataclass
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener


@dataclass(frozen=True)
class PermissionExecution:
    outcome: str
    detail: str
    status_code: int | None = None


def validate_local_request(base_url: str, endpoint: str, credential: str | None) -> PermissionExecution:
    """Validate an executable permission test without storing or exposing a credential."""

    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"localhost", "127.0.0.1"}:
        return PermissionExecution("skipped", "目标不是已允许的本地 URL。")
    if not credential:
        return PermissionExecution("skipped", "未提供运行时凭据；未发起请求。")
    target = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
    if urlparse(target).hostname != parsed.hostname:
        return PermissionExecution("skipped", "接口路径改变了目标主机。")
    return PermissionExecution("ready", "本地权限请求已通过范围与凭据前置校验。")


class _NoRedirect(HTTPRedirectHandler):
    """Do not let a local endpoint redirect a regression request elsewhere."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _is_same_target(base_url: str, request_url: str) -> bool:
    base = urlparse(base_url)
    target = urlparse(request_url)
    return (
        target.scheme == base.scheme
        and target.hostname == base.hostname
        and target.port == base.port
        and not target.username
        and not target.password
    )


def _request_status(opener, request: Request) -> int:
    try:
        with opener.open(request, timeout=5) as response:
            return int(response.status)
    except HTTPError as error:
        return int(error.code)


def execute_permission_request(
    base_url: str,
    endpoint: str,
    method: str,
    expected_access: str,
    authentication_type: str,
    credential: str | None,
    login_endpoint: str = "/test-login",
) -> PermissionExecution:
    """Run one scoped Cookie or Bearer permission check without retaining credentials.

    The returned detail deliberately contains only a status class, never a credential,
    response body, response headers, or endpoint query values.
    """

    anonymous_denial = credential is None and expected_access == "deny"
    validation = validate_local_request(base_url, endpoint, credential or "anonymous-scope-check")
    if validation.outcome != "ready":
        return validation
    if credential is None and not anonymous_denial:
        return PermissionExecution("skipped", "允许规则必须提供运行时凭据；未发起请求。")
    if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        return PermissionExecution("skipped", "HTTP 方法不在允许的权限回归范围内。")
    if expected_access not in {"allow", "deny"}:
        return PermissionExecution("skipped", "预期权限必须为 allow 或 deny。")
    if authentication_type not in {"bearer", "cookie"}:
        return PermissionExecution("skipped", "认证方式仅支持 Bearer Token 或 Cookie。")

    target_url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
    if not _is_same_target(base_url, target_url):
        return PermissionExecution("skipped", "接口路径改变了目标主机、端口或协议。")

    headers: dict[str, str] = {}
    cookie_jar = CookieJar()
    opener = build_opener(_NoRedirect(), HTTPCookieProcessor(cookie_jar))
    if authentication_type == "bearer" and credential:
        headers["Authorization"] = f"Bearer {credential}"
    elif authentication_type == "cookie" and credential:
        login_url = urljoin(base_url.rstrip("/") + "/", login_endpoint.lstrip("/"))
        if not _is_same_target(base_url, login_url):
            return PermissionExecution("skipped", "Cookie 登录路径改变了目标主机、端口或协议。")
        try:
            login_status = _request_status(
                opener,
                Request(login_url, method="POST", headers={"Authorization": f"Bearer {credential}"}),
            )
        except (URLError, OSError):
            return PermissionExecution("error", "本地 Cookie 登录请求无法完成；未记录响应内容。")
        if not 200 <= login_status < 300 or not cookie_jar:
            return PermissionExecution("error", "本地 Cookie 登录未获得有效会话；未记录响应内容。", login_status)

    try:
        status_code = _request_status(opener, Request(target_url, method=method.upper(), headers=headers))
    except (URLError, OSError):
        return PermissionExecution("error", "本地权限请求无法完成；未记录响应内容。")

    actual_access = "allow" if 200 <= status_code < 300 else "deny" if status_code in {401, 403} else "other"
    if actual_access == expected_access:
        return PermissionExecution("passed", f"服务端返回 {status_code}，与权限矩阵预期一致。", status_code)
    return PermissionExecution("failed", f"服务端返回 {status_code}，与权限矩阵预期不一致。", status_code)
