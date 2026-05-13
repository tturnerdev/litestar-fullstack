"""Unit tests for attachment service helpers."""

from __future__ import annotations

import pytest

from app.domain.attachments.services._attachment import _sanitize_filename

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("report.pdf", "report.pdf"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\bob\\photo.PNG", "photo.PNG"),
        ("my file (final).txt", "my-file-final-.txt"),
        ("", "file"),
        (None, "file"),
        ("...", "file"),
        ("résumé.doc", "r-sum-.doc"),
    ],
)
def test_sanitize_filename(raw: str | None, expected: str) -> None:
    assert _sanitize_filename(raw) == expected
