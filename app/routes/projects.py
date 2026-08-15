"""Authenticated project and asset registration routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.checks import run_project_checks
from app.discovery import import_registered_project_files
from app.projects import (
    ASSET_TYPES,
    TARGET_TYPES,
    ValidationError,
    add_asset,
    add_target,
    create_project,
    create_remediation_task,
    delete_project,
    get_project,
    list_assets,
    list_check_results,
    list_findings,
    list_import_records,
    list_projects,
    list_regression_verifications,
    list_remediation_tasks,
    list_targets,
    record_regression_verification,
    update_finding_status,
    update_remediation_task_status,
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
                "check_results": list_check_results(database_path(request), project_id),
                "findings": list_findings(database_path(request), project_id),
                "target_types": TARGET_TYPES,
                "asset_types": ASSET_TYPES,
                "csrf_token": issue_csrf_token(request),
                "error": error,
            },
            status_code=response_status,
        )

    def findings_page(request: Request, project_id: int, error: str | None = None, response_status: int = 200):
        project = project_or_404(request, project_id)
        return templates.TemplateResponse(
            request=request,
            name="findings.html",
            context={
                "project": project,
                "findings": list_findings(database_path(request), project_id),
                "tasks": list_remediation_tasks(database_path(request), project_id),
                "verifications": list_regression_verifications(database_path(request), project_id),
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

    @router.post("/projects/{project_id}/delete", response_class=HTMLResponse)
    async def delete_registered_project(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        project_or_404(request, project_id)
        form = await request.form()
        if not form_is_valid(request, form):
            return project_page(request, project_id, "请求已失效，请重试。", status.HTTP_403_FORBIDDEN)
        try:
            delete_project(database_path(request), project_id, str(form.get("confirmation_name", "")))
        except ValidationError as error:
            return project_page(request, project_id, str(error), status.HTTP_422_UNPROCESSABLE_CONTENT)
        return RedirectResponse("/projects", status_code=status.HTTP_303_SEE_OTHER)

    @router.get("/projects/{project_id}", response_class=HTMLResponse)
    async def project_detail(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        return project_page(request, project_id)

    @router.get("/projects/{project_id}/findings", response_class=HTMLResponse)
    async def findings(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        return findings_page(request, project_id)

    async def finding_form_or_error(request: Request, project_id: int):
        form = await request.form()
        if not form_is_valid(request, form):
            return None, findings_page(request, project_id, "请求已失效，请重试。", status.HTTP_403_FORBIDDEN)
        return form, None

    @router.post("/projects/{project_id}/findings/{finding_id}/status", response_class=HTMLResponse)
    async def change_finding_status(request: Request, project_id: int, finding_id: int):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        form, error_page = await finding_form_or_error(request, project_id)
        if error_page:
            return error_page
        try:
            update_finding_status(database_path(request), project_id, finding_id, str(form.get("status", "")))
        except ValidationError as error:
            return findings_page(request, project_id, str(error), status.HTTP_422_UNPROCESSABLE_CONTENT)
        return RedirectResponse(f"/projects/{project_id}/findings", status_code=status.HTTP_303_SEE_OTHER)

    @router.post("/projects/{project_id}/findings/{finding_id}/tasks", response_class=HTMLResponse)
    async def create_finding_task(request: Request, project_id: int, finding_id: int):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        project_or_404(request, project_id)
        form, error_page = await finding_form_or_error(request, project_id)
        if error_page:
            return error_page
        try:
            update_finding_status(database_path(request), project_id, finding_id, "confirmed")
            create_remediation_task(
                database_path(request),
                finding_id,
                str(form.get("root_cause", "")),
                str(form.get("recommendation", "")),
                str(form.get("owner", "")),
                str(form.get("due_date", "")),
            )
        except ValidationError as error:
            return findings_page(request, project_id, str(error), status.HTTP_422_UNPROCESSABLE_CONTENT)
        return RedirectResponse(f"/projects/{project_id}/findings", status_code=status.HTTP_303_SEE_OTHER)

    @router.post("/projects/{project_id}/findings/{finding_id}/tasks/status", response_class=HTMLResponse)
    async def change_task_status(request: Request, project_id: int, finding_id: int):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        form, error_page = await finding_form_or_error(request, project_id)
        if error_page:
            return error_page
        try:
            update_remediation_task_status(database_path(request), project_id, finding_id, str(form.get("status", "")))
        except ValidationError as error:
            return findings_page(request, project_id, str(error), status.HTTP_422_UNPROCESSABLE_CONTENT)
        return RedirectResponse(f"/projects/{project_id}/findings", status_code=status.HTTP_303_SEE_OTHER)

    @router.post("/projects/{project_id}/findings/{finding_id}/verifications", response_class=HTMLResponse)
    async def create_regression_verification(request: Request, project_id: int, finding_id: int):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        form, error_page = await finding_form_or_error(request, project_id)
        if error_page:
            return error_page
        try:
            record_regression_verification(
                database_path(request),
                project_id,
                finding_id,
                str(form.get("outcome", "")),
                str(form.get("detail", "")),
            )
        except ValidationError as error:
            return findings_page(request, project_id, str(error), status.HTTP_422_UNPROCESSABLE_CONTENT)
        return RedirectResponse(f"/projects/{project_id}/findings", status_code=status.HTTP_303_SEE_OTHER)

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

    @router.post("/projects/{project_id}/checks", response_class=HTMLResponse)
    async def run_checks(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect is not None:
            return redirect
        project_or_404(request, project_id)
        form = await request.form()
        if not form_is_valid(request, form):
            return project_page(request, project_id, "请求已失效，请重试。", status.HTTP_403_FORBIDDEN)
        run_project_checks(database_path(request), project_id)
        return RedirectResponse(f"/projects/{project_id}", status_code=status.HTTP_303_SEE_OTHER)

    return router
