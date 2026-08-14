"""Local-only FastAPI authorization target for permission-regression tests."""

from __future__ import annotations

import hmac
import os
from hashlib import sha256
from typing import Final

from fastapi import FastAPI, Header, HTTPException, Request, Response, status

app = FastAPI(title="Local FastAPI Permission Target", docs_url=None, redoc_url=None)

COOKIE_NAME: Final = "local_target_session"
TOKEN_ENVIRONMENT: Final = {
    "user-a": "FASTAPI_TARGET_USER_A_TOKEN",
    "user-b": "FASTAPI_TARGET_USER_B_TOKEN",
    "admin": "FASTAPI_TARGET_ADMIN_TOKEN",
}


def _configured_token(principal: str) -> str:
    return os.getenv(TOKEN_ENVIRONMENT[principal], "")


def _principal_for_token(candidate: str) -> str | None:
    """Return a configured test principal without logging the supplied token."""

    if not candidate:
        return None
    for principal in TOKEN_ENVIRONMENT:
        expected = _configured_token(principal)
        if expected and hmac.compare_digest(candidate, expected):
            return principal
    return None


def _cookie_signature(principal: str) -> str:
    return hmac.new(
        _configured_token(principal).encode("utf-8"),
        principal.encode("utf-8"),
        sha256,
    ).hexdigest()


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, separator, token = authorization.partition(" ")
    if separator and scheme.lower() == "bearer" and token:
        return token
    return None


def _principal_from_cookie(request: Request) -> str | None:
    encoded_session = request.cookies.get(COOKIE_NAME, "")
    principal, separator, signature = encoded_session.partition("|")
    if not separator or principal not in TOKEN_ENVIRONMENT:
        return None
    expected = _configured_token(principal)
    if expected and signature and hmac.compare_digest(signature, _cookie_signature(principal)):
        return principal
    return None


def authenticated_principal(request: Request, authorization: str | None = Header(default=None)) -> str:
    principal = _principal_for_token(_bearer_token(authorization) or "") or _principal_from_cookie(request)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return principal


def owner_or_admin(request: Request, owner: str, authorization: str | None = Header(default=None)) -> str:
    principal = authenticated_principal(request, authorization)
    if principal not in {owner, "admin"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return principal


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/test-login", status_code=status.HTTP_204_NO_CONTENT)
def test_login(response: Response, authorization: str | None = Header(default=None)) -> None:
    principal = _principal_for_token(_bearer_token(authorization) or "")
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    response.set_cookie(
        key=COOKIE_NAME,
        value=f"{principal}|{_cookie_signature(principal)}",
        httponly=True,
        samesite="strict",
        secure=False,
    )


@app.get("/api/profiles/{owner}")
def profile(owner: str, request: Request, authorization: str | None = Header(default=None)) -> dict[str, str]:
    owner_or_admin(request, owner, authorization)
    return {"profile": owner}


@app.post("/api/orders/{owner}", status_code=status.HTTP_204_NO_CONTENT)
def update_order(owner: str, request: Request, authorization: str | None = Header(default=None)) -> None:
    owner_or_admin(request, owner, authorization)


@app.get("/api/admin/stats")
def admin_stats(request: Request, authorization: str | None = Header(default=None)) -> dict[str, int]:
    principal = authenticated_principal(request, authorization)
    if principal != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return {"active_test_accounts": 3}
