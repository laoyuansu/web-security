from app.permission_runner import validate_local_request


def test_permission_execution_requires_runtime_credential_and_local_url() -> None:
    assert validate_local_request("http://127.0.0.1:8000", "/api/orders", None).outcome == "skipped"
    assert validate_local_request("https://example.com", "/api/orders", "test-only").outcome == "skipped"
    assert validate_local_request("http://localhost:8000", "/api/orders", "test-only").outcome == "ready"
