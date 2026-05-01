"""Bulk import schemas for admin CSV upload."""

from __future__ import annotations

from typing import Any

from app.lib.schema import CamelizedBaseStruct


class BulkImportPreviewRow(CamelizedBaseStruct, kw_only=True):
    """A single parsed row from a CSV preview."""

    row_number: int
    action: str  # "create", "update", "skip"
    data: dict[str, Any]
    errors: list[str] = []


class BulkImportPreview(CamelizedBaseStruct, kw_only=True):
    """Result of previewing a CSV import without persisting changes."""

    total_rows: int
    valid_rows: int
    error_rows: int
    rows: list[BulkImportPreviewRow]


class BulkImportResult(CamelizedBaseStruct, kw_only=True):
    """Result of executing a bulk CSV import."""

    created: int
    updated: int
    skipped: int
    errors: list[str]
