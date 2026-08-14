"""Local-only FastAPI entry point for the security self-check workbench."""

from __future__ import annotations

import hmac
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.config import Settings, get_settings
from app.database import initialize_database
from app.projects import list_projects
from app.routes.matrix import build_matrix_router
from app.routes.projects import build_project_router
from app.routes.reports import build_report_router
from app.security.auth import (
    csrf_token_is_valid,
    establish_authenticated_session,
    is_authenticated,
    issue_csrf_token,
    login_required,
)

APPLICATION_DIRECTORY = Path(__file__).resolve().parent
SESSION_MAX_AGE_SECONDS = 8 * 60 * 60


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create an app that fails closed when required local secrets are missing."""

    active_settings = settings or get_settings()
    @asynccontextmanager
    async def lifespan(_application: FastAPI):
        initialize_database(active_settings.database_path)
        yield

    application = FastAPI(
        title="本地 Web 安全自查与修复台",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )
    application.state.settings = active_settings
    application.add_middleware(
        SessionMiddleware,
        secret_key=active_settings.session_secret,
        session_cookie="security_workbench_session",
        max_age=SESSION_MAX_AGE_SECONDS,
        same_site="lax",
        https_only=False,
    )
    application.mount("/static", StaticFiles(directory=APPLICATION_DIRECTORY / "static"), name="static")
    templates = Jinja2Templates(directory=str(APPLICATION_DIRECTORY / "templates"))
    application.include_router(build_project_router(templates))
    application.include_router(build_matrix_router(templates))
    application.include_router(build_report_router(templates))

    @application.middleware("http")
    async def apply_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; img-src 'self'; "
            "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @application.get("/", include_in_schema=False)
    async def index() -> RedirectResponse:
        return RedirectResponse("/dashboard", status_code=303)

    @application.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if is_authenticated(request):
            return RedirectResponse("/dashboard", status_code=303)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"csrf_token": issue_csrf_token(request), "error": None},
        )

    @application.post("/login", response_class=HTMLResponse)
    async def login(request: Request):
        form = await request.form()
        submitted_csrf_token = form.get("csrf_token")
        if not csrf_token_is_valid(request, submitted_csrf_token if isinstance(submitted_csrf_token, str) else None):
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"csrf_token": issue_csrf_token(request), "error": "请求已失效，请重试。"},
                status_code=status.HTTP_403_FORBIDDEN,
            )

        username = str(form.get("username", "")).strip()
        password = str(form.get("password", ""))
        if not (
            hmac.compare_digest(username, active_settings.admin_username)
            and hmac.compare_digest(password, active_settings.admin_password)
        ):
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"csrf_token": issue_csrf_token(request), "error": "用户名或密码不正确。"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        establish_authenticated_session(request, username)
        return RedirectResponse("/dashboard", status_code=303)

    @application.post("/logout")
    async def logout(request: Request) -> RedirectResponse:
        form = await request.form()
        submitted_csrf_token = form.get("csrf_token")
        if not csrf_token_is_valid(request, submitted_csrf_token if isinstance(submitted_csrf_token, str) else None):
            return RedirectResponse("/login", status_code=303)
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    @application.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "csrf_token": issue_csrf_token(request),
                "username": request.session.get("username", active_settings.admin_username),
                "projects": list_projects(active_settings.database_path),
            },
        )

    return application


app = create_app()
