"""Authenticated local report and redacted-backup download routes."""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from app.projects import get_project
from app.reports import build_markdown_report, build_redacted_backup
from app.security.auth import login_required


def build_report_router(templates: Jinja2Templates) -> APIRouter:
    router = APIRouter()

    def verify_project(request: Request, project_id: int):
        project = get_project(request.app.state.settings.database_path, project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="项目不存在。")
        return project

    @router.get("/projects/{project_id}/report", response_class=HTMLResponse)
    async def report_page(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect:
            return redirect
        return templates.TemplateResponse(request=request, name="report.html", context={"project": verify_project(request, project_id)})

    @router.get("/projects/{project_id}/report/markdown")
    async def download_markdown(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect:
            return redirect
        verify_project(request, project_id)
        return Response(build_markdown_report(request.app.state.settings.database_path, project_id), media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": "attachment; filename=security-report.md"})

    @router.get("/projects/{project_id}/backup.json")
    async def download_backup(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect:
            return redirect
        verify_project(request, project_id)
        return Response(build_redacted_backup(request.app.state.settings.database_path, project_id), media_type="application/json", headers={"Content-Disposition": "attachment; filename=security-backup.json"})

    return router
