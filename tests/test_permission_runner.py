from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from app.permission_runner import execute_permission_request, validate_local_request


def test_permission_execution_requires_runtime_credential_and_local_url() -> None:
    assert validate_local_request("http://127.0.0.1:8000", "/api/orders", None).outcome == "skipped"
    assert validate_local_request("https://example.com", "/api/orders", "test-only").outcome == "skipped"
    assert validate_local_request("http://localhost:8000", "/api/orders", "test-only").outcome == "ready"


class _PermissionHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path == "/test-login" and self.headers.get("Authorization") == "Bearer cookie-token":
            self.send_response(204)
            self.send_header("Set-Cookie", "session=ok; HttpOnly; SameSite=Strict")
            self.end_headers()
            return
        self._send_protected_response()

    def do_GET(self) -> None:
        self._send_protected_response()

    def _send_protected_response(self) -> None:
        valid_bearer = self.headers.get("Authorization") == "Bearer bearer-token"
        valid_cookie = "session=ok" in self.headers.get("Cookie", "")
        self.send_response(200 if valid_bearer or valid_cookie else 403)
        self.end_headers()

    def log_message(self, format: str, *args) -> None:
        return


def test_permission_execution_compares_cookie_and_bearer_results_without_exposing_credential() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PermissionHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        bearer = execute_permission_request(base_url, "/allowed", "GET", "allow", "bearer", "bearer-token")
        denied = execute_permission_request(base_url, "/allowed", "GET", "deny", "bearer", "bearer-token")
        cookie = execute_permission_request(base_url, "/allowed", "GET", "allow", "cookie", "cookie-token")
        guest = execute_permission_request(base_url, "/allowed", "GET", "deny", "bearer", None)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

    assert (bearer.outcome, bearer.status_code) == ("passed", 200)
    assert (denied.outcome, denied.status_code) == ("failed", 200)
    assert (cookie.outcome, cookie.status_code) == ("passed", 200)
    assert (guest.outcome, guest.status_code) == ("passed", 403)
    assert "bearer-token" not in bearer.detail
    assert "cookie-token" not in cookie.detail
