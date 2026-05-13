"""Tests for SecurityHeadersMiddleware."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from litestar.enums import ScopeType

from app.lib.middleware import SecurityHeadersMiddleware

pytestmark = pytest.mark.anyio


def _make_scope(**overrides: Any) -> dict[str, Any]:
    return {"type": ScopeType.HTTP, **overrides}


async def test_adds_security_headers() -> None:
    captured_messages: list[dict[str, Any]] = []

    async def mock_send(message: dict[str, Any]) -> None:
        captured_messages.append(message)

    async def mock_app(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "headers": []})

    middleware = SecurityHeadersMiddleware(app=mock_app)
    await middleware(_make_scope(), AsyncMock(), mock_send)

    msg = captured_messages[0]
    headers = dict(msg["headers"])
    assert headers[b"x-content-type-options"] == b"nosniff"
    assert headers[b"x-frame-options"] == b"DENY"
    assert headers[b"referrer-policy"] == b"strict-origin-when-cross-origin"
    assert b"permissions-policy" in headers
    assert b"strict-transport-security" in headers


async def test_preserves_existing_headers() -> None:
    captured_messages: list[dict[str, Any]] = []

    async def mock_send(message: dict[str, Any]) -> None:
        captured_messages.append(message)

    async def mock_app(scope: Any, receive: Any, send: Any) -> None:
        await send({
            "type": "http.response.start",
            "headers": [(b"content-type", b"text/html")],
        })

    middleware = SecurityHeadersMiddleware(app=mock_app)
    await middleware(_make_scope(), AsyncMock(), mock_send)

    header_keys = [h[0] for h in captured_messages[0]["headers"]]
    assert b"content-type" in header_keys
    assert b"x-frame-options" in header_keys


async def test_non_response_start_passthrough() -> None:
    captured_messages: list[dict[str, Any]] = []

    async def mock_send(message: dict[str, Any]) -> None:
        captured_messages.append(message)

    async def mock_app(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.body", "body": b"hello"})

    middleware = SecurityHeadersMiddleware(app=mock_app)
    await middleware(_make_scope(), AsyncMock(), mock_send)

    assert captured_messages[0]["type"] == "http.response.body"
    assert "headers" not in captured_messages[0]
