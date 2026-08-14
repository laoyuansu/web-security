"""Session and CSRF helpers for the workbench's independent local login."""

from __future__ import annotations

import hmac
import secrets

from fastapi import Request
from fastapi.responses import RedirectResponse

AUTHENTICATED_KEY = "authenticated"
CSRF_TOKEN_KEY = "csrf_token"
LOGIN_PATH = "/login"


def issue_csrf_token(request: Request) -> str:
    """Create or return the current session's CSRF token."""

    token = request.session.get(CSRF_TOKEN_KEY)
    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        request.session[CSRF_TOKEN_KEY] = token
    return token


def csrf_token_is_valid(request: Request, submitted_token: str | None) -> bool:
    """Use a constant-time comparison for state-changing form requests."""

    expected_token = request.session.get(CSRF_TOKEN_KEY)
    return isinstance(expected_token, str) and isinstance(submitted_token, str) and hmac.compare_digest(
        expected_token, submitted_token
    )


def is_authenticated(request: Request) -> bool:
    """Return whether this session completed the independent local login."""

    return request.session.get(AUTHENTICATED_KEY) is True


def login_required(request: Request) -> RedirectResponse | None:
    """Redirect unauthenticated requests to the login page."""

    if is_authenticated(request):
        return None
    return RedirectResponse(LOGIN_PATH, status_code=303)


def establish_authenticated_session(request: Request, username: str) -> None:
    """Rotate session contents after successful authentication."""

    request.session.clear()
    request.session[AUTHENTICATED_KEY] = True
    request.session["username"] = username
    request.session[CSRF_TOKEN_KEY] = secrets.token_urlsafe(32)
