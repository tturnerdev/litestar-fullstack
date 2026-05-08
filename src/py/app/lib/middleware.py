"""Application middleware."""

from __future__ import annotations

from typing import TYPE_CHECKING

from litestar.middleware import AbstractMiddleware
from litestar.status_codes import HTTP_200_OK

if TYPE_CHECKING:
    from litestar import Request, Response
    from litestar.types import ASGIApp, Message, Receive, Scope, Send


class SecurityHeadersMiddleware(AbstractMiddleware):
    """Adds standard security headers to all HTTP responses."""

    scopes = {1}  # HTTP scope only

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = dict(scope.get("response_headers", []))
                security_headers: list[tuple[bytes, bytes]] = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                ]
                existing = message.get("headers", [])
                message["headers"] = [*existing, *security_headers]
            await send(message)

        await self.app(scope, receive, send_with_headers)
