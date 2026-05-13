"""Tests for object storage backend registration (``app.lib.storage``)."""

from __future__ import annotations

import pytest
from advanced_alchemy.types.file_object import FileObject, storages
from advanced_alchemy.types.file_object.backends.obstore import ObstoreBackend

from app.lib.settings import get_settings
from app.lib.storage import register_storage_backends

pytestmark = pytest.mark.anyio


def test_register_storage_backends_registers_uploads_backend() -> None:
    key = get_settings().storage.REGISTRY_KEY
    register_storage_backends()
    assert storages.is_registered(key)
    assert isinstance(storages.get_backend(key), ObstoreBackend)


def test_register_storage_backends_is_idempotent() -> None:
    key = get_settings().storage.REGISTRY_KEY
    register_storage_backends()
    backend = storages.get_backend(key)
    register_storage_backends()
    assert storages.get_backend(key) is backend


async def test_storage_backend_round_trip() -> None:
    register_storage_backends()
    key = get_settings().storage.REGISTRY_KEY
    obj = FileObject(
        backend=key,
        filename="unit-tests/storage/hello.txt",
        content=b"hello world",
        content_type="text/plain",
    )
    saved = await obj.save_async()
    try:
        assert saved.size == len(b"hello world")
        assert await saved.get_content_async() == b"hello world"
        # a fresh handle to the same path resolves the same bytes
        assert await FileObject(backend=key, filename=saved.path).get_content_async() == b"hello world"
    finally:
        await saved.delete_async()
