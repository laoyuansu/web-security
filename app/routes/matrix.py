"""Authenticated permission-matrix configuration routes without credential collection."""

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.projects import (
    ValidationError,
    add_resource,
    add_role,
    add_test_account_mapping,
    get_project,
    list_matrix_rows,
    list_resources,
    list_roles,
    list_test_account_mappings,
    set_permission_rule,
)
from app.security.auth import csrf_token_is_valid, issue_csrf_token, login_required


def build_matrix_router(templates: Jinja2Templates) -> APIRouter:
    router = APIRouter()

    def page(request: Request, project_id: int, error: str | None = None, response_status: int = 200):
        database_path = request.app.state.settings.database_path
        if get_project(database_path, project_id) is None:
            raise HTTPException(status_code=404, detail="项目不存在。")
        return templates.TemplateResponse(
            request=request,
            name="matrix.html",
            context={
                "project_id": project_id,
                "roles": list_roles(database_path, project_id),
                "resources": list_resources(database_path, project_id),
                "rules": list_matrix_rows(database_path, project_id),
                "accounts": list_test_account_mappings(database_path, project_id),
                "csrf_token": issue_csrf_token(request),
                "error": error,
            },
            status_code=response_status,
        )

    async def form_or_error(request: Request, project_id: int):
        form = await request.form()
        token = form.get("csrf_token")
        if not csrf_token_is_valid(request, token if isinstance(token, str) else None):
            return None, page(request, project_id, "请求已失效，请重试。", status.HTTP_403_FORBIDDEN)
        return form, None

    @router.get("/projects/{project_id}/matrix", response_class=HTMLResponse)
    async def matrix(request: Request, project_id: int):
        redirect = login_required(request)
        return redirect or page(request, project_id)

    @router.post("/projects/{project_id}/matrix/roles", response_class=HTMLResponse)
    async def create_role(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect:
            return redirect
        form, error_page = await form_or_error(request, project_id)
        if error_page:
            return error_page
        try:
            add_role(request.app.state.settings.database_path, project_id, str(form.get("name", "")))
        except ValidationError as error:
            return page(request, project_id, str(error), status.HTTP_422_UNPROCESSABLE_CONTENT)
        return RedirectResponse(f"/projects/{project_id}/matrix", status_code=303)

    @router.post("/projects/{project_id}/matrix/resources", response_class=HTMLResponse)
    async def create_resource(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect:
            return redirect
        form, error_page = await form_or_error(request, project_id)
        if error_page:
            return error_page
        try:
            add_resource(request.app.state.settings.database_path, project_id, str(form.get("name", "")), str(form.get("method", "")), str(form.get("endpoint", "")))
        except ValidationError as error:
            return page(request, project_id, str(error), status.HTTP_422_UNPROCESSABLE_CONTENT)
        return RedirectResponse(f"/projects/{project_id}/matrix", status_code=303)

    @router.post("/projects/{project_id}/matrix/rules", response_class=HTMLResponse)
    async def create_rule(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect:
            return redirect
        form, error_page = await form_or_error(request, project_id)
        if error_page:
            return error_page
        try:
            set_permission_rule(request.app.state.settings.database_path, project_id, int(form["role_id"]), int(form["resource_id"]), str(form.get("expected_access", "")))
        except (KeyError, ValueError, ValidationError) as error:
            return page(request, project_id, str(error), status.HTTP_422_UNPROCESSABLE_CONTENT)
        return RedirectResponse(f"/projects/{project_id}/matrix", status_code=303)

    @router.post("/projects/{project_id}/matrix/accounts", response_class=HTMLResponse)
    async def create_account_mapping(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect:
            return redirect
        form, error_page = await form_or_error(request, project_id)
        if error_page:
            return error_page
        try:
            add_test_account_mapping(request.app.state.settings.database_path, project_id, int(form["role_id"]), str(form.get("account_name", "")), str(form.get("authentication_type", "")), str(form.get("credential_source", "")))
        except (KeyError, ValueError, ValidationError) as error:
            return page(request, project_id, str(error), status.HTTP_422_UNPROCESSABLE_CONTENT)
        return RedirectResponse(f"/projects/{project_id}/matrix", status_code=303)

    return router
