"""Authenticated project and asset registration routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.discovery import import_registered_project_files
from app.projects import (
    ASSET_TYPES,
    TARGET_TYPES,
    ValidationError,
    add_asset,
    add_target,
    create_project,
    get_project,
    list_assets,
    list_import_records,
    list_projects,
    list_targets,
)
from app.security.auth import csrf_token_is_valid, issue_csrf_token, login_required


def build_project_router(templates: Jinja2Templates) -> APIRouter:
    """Build routes that never expose project metadata before local login."""

    router = APIRouter()

    def database_path(request: Request):
        return request.app.state.settings.database_path

    def project_or_404(request: Request, project_id: int):
        project = get_project(database_path(request), project_id)
        if project is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="项目不存在。")
        return project

    def projects_page(request: Request, error: str | None = None, response_status: int = 200):
        return templates.TemplateResponse(
            request=request,
            name="projects.html",
            context={
                "projects": list_projects(database_path(request)),
                "csrf_token": issue_csrf_token(request),
                "error": error,
            },
            status_code=response_status,
        )

    def project_page(request: Request, project_id: int, error: str | None = None, response_status: int = 200):
        project = project_or_404(request, project_id)
        return templates.TemplateResponse(
            request=request,
            name="project_detail.html",
            context={
                "project": project,
                "targets": list_targets(database_path(request), project_id),
                "assets": list_assets(database_path(request), project_id),
                "import_records": list_import_records(database_path(request), project_id),
                "target_types": TARGET_TYPES,
                "asset_types": ASSET_TYPES,
                "csrf_token": issue_csrf_token(request),
                "error": error,
            },
            status_code=response_status,
        )

    def form_is_valid(request: Request, form) -> bool:
        token = form.get("csrf_token")
        return csrf_token_is_valid(request, token if isinstance(token, str) else None)

    @router.get("/projects", response_class=HTMLResponse)
    async def projects(request: Request):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        return projects_page(request)

    @router.post("/projects", response_class=HTMLResponse)
    async def add_project(request: Request):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        form = await request.form()
        if not form_is_valid(request, form):
            return projects_page(request, "请求已失效，请重试。", status.HTTP_403_FORBIDDEN)
        try:
            project = create_project(
                database_path(request), str(form.get("name", "")), str(form.get("description", ""))
            )
        except ValidationError as error:
            return projects_page(request, str(error), status.HTTP_422_UNPROCESSABLE_CONTENT)
        return RedirectResponse(f"/projects/{project.id}", status_code=status.HTTP_303_SEE_OTHER)

    @router.get("/projects/{project_id}", response_class=HTMLResponse)
    async def project_detail(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        return project_page(request, project_id)

    @router.post("/projects/{project_id}/targets", response_class=HTMLResponse)
    async def add_project_target(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        project_or_404(request, project_id)
        form = await request.form()
        if not form_is_valid(request, form):
            return project_page(request, project_id, "请求已失效，请重试。", status.HTTP_403_FORBIDDEN)
        try:
            add_target(
                database_path(request),
                project_id,
                str(form.get("target_type", "")),
                str(form.get("value", "")),
            )
        except ValidationError as error:
            return project_page(request, project_id, str(error), status.HTTP_422_UNPROCESSABLE_CONTENT)
        return RedirectResponse(f"/projects/{project_id}", status_code=status.HTTP_303_SEE_OTHER)

    @router.post("/projects/{project_id}/assets", response_class=HTMLResponse)
    async def add_project_asset(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        project_or_404(request, project_id)
        form = await request.form()
        if not form_is_valid(request, form):
            return project_page(request, project_id, "请求已失效，请重试。", status.HTTP_403_FORBIDDEN)
        try:
            add_asset(
                database_path(request),
                project_id,
                str(form.get("asset_type", "")),
                str(form.get("name", "")),
                str(form.get("value", "")),
            )
        except ValidationError as error:
            return project_page(request, project_id, str(error), status.HTTP_422_UNPROCESSABLE_CONTENT)
        return RedirectResponse(f"/projects/{project_id}", status_code=status.HTTP_303_SEE_OTHER)

    @router.post("/projects/{project_id}/imports", response_class=HTMLResponse)
    async def import_project_files(request: Request, project_id: int):
        """Import only known manifests from already-registered project directories."""

        redirect = login_required(request)
        if redirect is not None:
            return redirect
        project_or_404(request, project_id)
        form = await request.form()
        if not form_is_valid(request, form):
            return project_page(request, project_id, "请求已失效，请重试。", status.HTTP_403_FORBIDDEN)
        import_registered_project_files(database_path(request), project_id)
        return RedirectResponse(f"/projects/{project_id}", status_code=status.HTTP_303_SEE_OTHER)

    return router
