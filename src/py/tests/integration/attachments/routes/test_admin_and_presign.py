"""Integration tests for the admin attachments and presigned-upload endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from httpx import AsyncClient


pytestmark = [pytest.mark.anyio, pytest.mark.integration]


async def test_admin_can_list_and_delete_any_attachment(
    seeded_client: AsyncClient,
    superuser_token_headers: dict[str, str],
    user_token_headers: dict[str, str],
) -> None:
    # a regular user uploads a file
    upload = await seeded_client.post(
        "/api/uploads",
        files={"data": ("notes.txt", b"some bytes", "text/plain")},
        headers=user_token_headers,
    )
    assert upload.status_code == 201
    attachment_id = upload.json()["id"]

    # superuser sees it in the admin list
    listing = await seeded_client.get("/api/admin/attachments", headers=superuser_token_headers)
    assert listing.status_code == 200
    ids = [item["id"] for item in listing.json()["items"]]
    assert attachment_id in ids

    # regular user is denied
    forbidden = await seeded_client.get("/api/admin/attachments", headers=user_token_headers)
    assert forbidden.status_code == 403

    # superuser deletes it (even though they aren't the uploader)
    removed = await seeded_client.delete(f"/api/admin/attachments/{attachment_id}", headers=superuser_token_headers)
    assert removed.status_code == 204
    # gone
    assert (await seeded_client.get(f"/api/uploads/{attachment_id}", headers=user_token_headers)).status_code == 404


async def test_presign_returns_400_for_unsupported_backend(
    seeded_client: AsyncClient,
    user_token_headers: dict[str, str],
) -> None:
    # tests run with STORAGE_BACKEND=memory which does not support presigning;
    # the endpoint should report this cleanly rather than raising 500.
    response = await seeded_client.post(
        "/api/uploads/presign",
        json={"filename": "anything.bin", "contentType": "application/octet-stream"},
        headers=user_token_headers,
    )
    assert response.status_code == 400


async def test_complete_upload_returns_400_when_object_missing(
    seeded_client: AsyncClient,
    user_token_headers: dict[str, str],
) -> None:
    response = await seeded_client.post(
        "/api/uploads/complete",
        json={
            "path": "attachment/does-not-exist.bin",
            "originalFilename": "does-not-exist.bin",
            "contentType": "application/octet-stream",
        },
        headers=user_token_headers,
    )
    assert response.status_code == 400
