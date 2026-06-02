"""
Test fixtures for the auth endpoints.

Currently provides a small helper to build a real starlette.Request object
that slowapi will accept (slowapi insists the request be a starlette.Request,
not a MagicMock, so decorators can introspect scope.client for the IP).
"""
from __future__ import annotations

from fastapi import Request


def make_test_request(
    path: str = "/api/v1/auth/login",
    method: str = "POST",
    ip: str = "127.0.0.1",
) -> Request:
    """Build a minimal but real starlette.Request with a client IP.

    Used by tests that call slowapi-decorated endpoints directly (the decorator
    inspects the request to derive the rate-limit key, so it can't be a Mock).
    """
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [(b"x-forwarded-for", ip.encode())],
        "query_string": b"",
        "client": (ip, 12345),
        "server": ("testserver", 80),
        "scheme": "http",
        "root_path": "",
        "asgi": {"version": "3.0", "spec_version": "2.0"},
        "http_version": "1.1",
        "extensions": {},
    }
    return Request(scope)
