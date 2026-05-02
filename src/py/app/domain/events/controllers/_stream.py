"""SSE event stream controller."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Any

import msgspec
from litestar import Controller, get
from litestar.di import Provide
from litestar.response import Stream

from app.db import models as m
from app.domain.events.deps import provide_event_subscriber
from app.domain.events.guards import requires_active_session
from app.domain.events.services import EventSubscriber

if TYPE_CHECKING:
    from litestar import Request
    from litestar.security.jwt import Token


class EventStreamController(Controller):
    """SSE endpoint for real-time event streaming.

    Opens a long-lived SSE connection for the authenticated user,
    subscribing to Redis Pub/Sub channels scoped to the user's teams
    and their personal notification channel.
    """

    path = "/api/events"
    tags = ["Events"]
    dependencies = {"event_subscriber": Provide(provide_event_subscriber)}

    @get(
        operation_id="StreamEvents",
        name="events:stream",
        path="/stream",
        summary="Stream real-time events via SSE",
        media_type="text/event-stream",
        guards=[requires_active_session],
        include_in_schema=False,
    )
    async def stream_events(
        self,
        request: Request[m.User, Token, Any],
        event_subscriber: EventSubscriber,
    ) -> Stream:
        """Open an SSE connection for the authenticated user.

        The stream delivers events scoped to the user's team(s) and
        user-specific notifications. The connection stays open
        indefinitely; the client should reconnect on disconnect.

        A heartbeat comment is sent every 30 seconds to keep the
        connection alive through proxies and load balancers.
        """
        user = request.user
        team_ids = [tm.team_id for tm in user.teams]

        async def event_generator() -> AsyncGenerator[bytes, None]:
            await event_subscriber.subscribe(team_ids, user.id)
            try:
                # Send initial heartbeat to confirm connection
                yield b": heartbeat\n\n"

                heartbeat_interval = 30  # seconds
                last_heartbeat = asyncio.get_running_loop().time()

                async for event_type, data in event_subscriber.listen():
                    sse_data = msgspec.json.encode(data).decode("utf-8")
                    yield f"event: {event_type}\ndata: {sse_data}\n\n".encode("utf-8")

                    # Send periodic heartbeats between events
                    now = asyncio.get_running_loop().time()
                    if now - last_heartbeat > heartbeat_interval:
                        yield b": heartbeat\n\n"
                        last_heartbeat = now
            finally:
                await event_subscriber.unsubscribe()

        return Stream(event_generator(), media_type="text/event-stream")
