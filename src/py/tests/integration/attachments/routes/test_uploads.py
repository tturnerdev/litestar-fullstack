"""Integration tests for the file upload (`/api/uploads`) endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from httpx import AsyncClient

pytestmark = [pytest.mark.anyio, pytest.mark.integration]


async def test_upload_get_download_and_list(
    seeded_client: AsyncClient,
    user_token_headers: dict[str, str],
) -> None:
    payload = b"hello, object storage"
    response = await seeded_client.post(
        "/api/uploads",
        files={"data": ("hello.txt", payload, "text/plain")},
        headers=user_token_headers,
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["originalFilename"] == "hello.txt"
    assert body["contentType"] == "text/plain"
    assert body["sizeBytes"] == len(payload)
    assert body["purpose"] == "attachment"
    assert body["checksumSha256"]
    assert body["downloadUrl"] == f"/api/uploads/{body['id']}/content"
    attachment_id = body["id"]

    get_response = await seeded_client.get(f"/api/uploads/{attachment_id}", headers=user_token_headers)
    assert get_response.status_code == 200
    assert get_response.json()["id"] == attachment_id

    content_response = await seeded_client.get(f"/api/uploads/{attachment_id}/content", headers=user_token_headers)
    assert content_response.status_code == 200
    assert content_response.content == payload

    list_response = await seeded_client.get("/api/uploads", headers=user_token_headers)
    assert list_response.status_code == 200
    assert attachment_id in [item["id"] for item in list_response.json()["items"]]


async def test_upload_empty_file_is_rejected(
    seeded_client: AsyncClient,
    user_token_headers: dict[str, str],
) -> None:
    response = await seeded_client.post(
        "/api/uploads",
        files={"data": ("empty.txt", b"", "text/plain")},
        headers=user_token_headers,
    )
    assert response.status_code == 400


async def test_delete_upload_removes_it(
    seeded_client: AsyncClient,
    user_token_headers: dict[str, str],
) -> None:
    response = await seeded_client.post(
        "/api/uploads",
        files={"data": ("doomed.txt", b"delete me", "text/plain")},
        headers=user_token_headers,
    )
    assert response.status_code == 201
    attachment_id = response.json()["id"]

    delete_response = await seeded_client.delete(f"/api/uploads/{attachment_id}", headers=user_token_headers)
    assert delete_response.status_code == 204

    get_response = await seeded_client.get(f"/api/uploads/{attachment_id}", headers=user_token_headers)
    assert get_response.status_code == 404


async def test_other_user_cannot_access_but_superuser_can(
    seeded_client: AsyncClient,
    superuser_token_headers: dict[str, str],
    user_token_headers: dict[str, str],
) -> None:
    # superuser uploads a file
    response = await seeded_client.post(
        "/api/uploads",
        files={"data": ("private.txt", b"top secret", "text/plain")},
        headers=superuser_token_headers,
    )
    assert response.status_code == 201
    attachment_id = response.json()["id"]

    # a regular, unrelated user cannot read it
    forbidden = await seeded_client.get(f"/api/uploads/{attachment_id}", headers=user_token_headers)
    assert forbidden.status_code == 403

    # the superuser can
    allowed = await seeded_client.get(f"/api/uploads/{attachment_id}", headers=superuser_token_headers)
    assert allowed.status_code == 200
