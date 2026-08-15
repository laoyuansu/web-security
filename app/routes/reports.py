"""Authenticated local report and redacted-backup download routes."""

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from app.projects import get_project
from app.reports import build_markdown_report, build_redacted_backup, import_redacted_backup
from app.security.auth import csrf_token_is_valid, issue_csrf_token, login_required

MAX_BACKUP_BYTES = 1_000_000


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
        return templates.TemplateResponse(
            request=request,
            name="report.html",
            context={"project": verify_project(request, project_id), "csrf_token": issue_csrf_token(request), "error": None},
        )

    @router.post("/projects/{project_id}/backup/import", response_class=HTMLResponse)
    async def import_backup(request: Request, project_id: int):
        redirect = login_required(request)
        if redirect:
            return redirect
        project = verify_project(request, project_id)
        form = await request.form()
        token = form.get("csrf_token")
        if not csrf_token_is_valid(request, token if isinstance(token, str) else None):
            return templates.TemplateResponse(
                request=request,
                name="report.html",
                context={"project": project, "csrf_token": issue_csrf_token(request), "error": "请求已失效，请重试。"},
                status_code=status.HTTP_403_FORBIDDEN,
            )
        uploaded = form.get("backup_file")
        if uploaded is None or not hasattr(uploaded, "read"):
            return templates.TemplateResponse(
                request=request,
                name="report.html",
                context={"project": project, "csrf_token": issue_csrf_token(request), "error": "请选择 JSON 备份文件。"},
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            )
        content = await uploaded.read(MAX_BACKUP_BYTES + 1)
        if len(content) > MAX_BACKUP_BYTES:
            return templates.TemplateResponse(
                request=request,
                name="report.html",
                context={"project": project, "csrf_token": issue_csrf_token(request), "error": "备份文件超过 1 MB 限制。"},
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            )
        try:
            imported = import_redacted_backup(request.app.state.settings.database_path, content.decode("utf-8"))
        except (UnicodeDecodeError, TypeError, ValueError) as error:
            return templates.TemplateResponse(
                request=request,
                name="report.html",
                context={"project": project, "csrf_token": issue_csrf_token(request), "error": f"备份导入失败：{error}"},
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            )
        return Response(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": f"/projects/{imported.id}"},
        )

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
