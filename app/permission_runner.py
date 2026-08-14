"""Permission-regression request builder with fail-closed credential handling."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlparse


@dataclass(frozen=True)
class PermissionExecution:
    outcome: str
    detail: str


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
