"""Integration tests for avatar and team-logo upload endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from httpx import AsyncClient
    from litestar.testing import AsyncTestClient

    from app.db import models as m

pytestmark = [pytest.mark.anyio, pytest.mark.integration]

_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16  # minimal-ish bytes; content is not validated


async def test_set_replace_and_clear_avatar(authenticated_client: AsyncTestClient) -> None:
    # set
    response = await authenticated_client.put(
        "/api/me/avatar",
        files={"data": ("me.png", _PNG, "image/png")},
    )
    assert response.status_code == 200, response.text
    user = response.json()
    avatar_url = user["avatarUrl"]
    assert avatar_url and avatar_url.startswith("/api/uploads/") and avatar_url.endswith("/content")

    # profile reflects it
    profile = await authenticated_client.get("/api/me")
    assert profile.json()["avatarUrl"] == avatar_url

    # the avatar content is downloadable
    content = await authenticated_client.get(avatar_url)
    assert content.status_code == 200
    assert content.content == _PNG

    # replace it
    replace = await authenticated_client.put(
        "/api/me/avatar",
        files={"data": ("new.png", _PNG + b"x", "image/png")},
    )
    assert replace.status_code == 200
    new_avatar_url = replace.json()["avatarUrl"]
    assert new_avatar_url != avatar_url
    # the old attachment is gone
    assert (await authenticated_client.get(avatar_url)).status_code == 404

    # clear it
    cleared = await authenticated_client.delete("/api/me/avatar")
    assert cleared.status_code == 200
    assert cleared.json()["avatarUrl"] is None
    assert (await authenticated_client.get(new_avatar_url)).status_code == 404


async def test_set_avatar_requires_authentication(client: AsyncClient) -> None:
    response = await client.put("/api/me/avatar", files={"data": ("me.png", _PNG, "image/png")})
    assert response.status_code == 401


async def test_avatar_is_served_inline_as_image(authenticated_client: AsyncTestClient) -> None:
    response = await authenticated_client.put(
        "/api/me/avatar",
        files={"data": ("me.png", _PNG, "image/png")},
    )
    assert response.status_code == 200
    avatar_url = response.json()["avatarUrl"]
    content = await authenticated_client.get(avatar_url)
    assert content.status_code == 200
    assert content.headers["content-type"].startswith("image/png")
    assert content.headers["content-disposition"].startswith("inline")
    assert content.headers.get("x-content-type-options") == "nosniff"


async def test_other_authenticated_user_can_view_avatar(
    seeded_client: AsyncClient,
    superuser_token_headers: dict[str, str],
    user_token_headers: dict[str, str],
) -> None:
    # superuser sets an avatar
    set_response = await seeded_client.put(
        "/api/me/avatar",
        files={"data": ("super.png", _PNG, "image/png")},
        headers=superuser_token_headers,
    )
    assert set_response.status_code == 200
    avatar_url = set_response.json()["avatarUrl"]

    # a different authenticated user can fetch it (avatars are intentionally
    # readable to any authenticated user so the UI can display them).
    other = await seeded_client.get(avatar_url, headers=user_token_headers)
    assert other.status_code == 200
    assert other.content == _PNG


async def test_team_admin_can_set_team_logo(
    authenticated_client: AsyncTestClient,
    test_team: m.Team,
) -> None:
    # test_user is an admin/owner of test_team
    response = await authenticated_client.put(
        f"/api/teams/{test_team.id}/logo",
        files={"data": ("logo.png", _PNG, "image/png")},
    )
    assert response.status_code == 200, response.text
    team = response.json()
    assert team["logoUrl"] and team["logoUrl"].startswith("/api/uploads/")

    fetched = await authenticated_client.get(f"/api/teams/{test_team.id}")
    assert fetched.json()["logoUrl"] == team["logoUrl"]

    content = await authenticated_client.get(team["logoUrl"])
    assert content.status_code == 200
    assert content.content == _PNG
