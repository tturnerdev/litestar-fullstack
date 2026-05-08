"""Bulk import schemas for phone numbers."""

from uuid import UUID

from app.lib.schema import CamelizedBaseStruct


class BulkImportRowPreview(CamelizedBaseStruct, kw_only=True):
    """Preview of a single row from bulk import."""

    row_number: int
    number: str
    user_id: str
    label: str | None = None
    number_type: str = "local"
    caller_id_name: str | None = None
    is_duplicate: bool = False


class BulkImportRowError(CamelizedBaseStruct, kw_only=True):
    """Validation errors for a single import row."""

    row_number: int
    errors: list[str]


class BulkImportPhoneNumberPreview(CamelizedBaseStruct, kw_only=True):
    """Preview summary for a phone number bulk import."""

    valid_rows: list[BulkImportRowPreview]
    error_rows: list[BulkImportRowError]
    duplicate_numbers: list[str]
    total_rows: int
    valid_count: int
    error_count: int
    duplicate_count: int


class BulkImportRowData(CamelizedBaseStruct, kw_only=True):
    """A single phone number to import."""

    number: str
    user_id: UUID
    label: str | None = None
    number_type: str = "local"
    caller_id_name: str | None = None
    team_id: UUID | None = None


class BulkImportPhoneNumberRequest(CamelizedBaseStruct, kw_only=True):
    """Request payload for bulk phone number import."""

    rows: list[BulkImportRowData]
    skip_duplicates: bool = True


class BulkImportPhoneNumberResult(CamelizedBaseStruct, kw_only=True):
    """Result summary from bulk phone number import."""

    created_count: int
    skipped_count: int
    error_count: int
    created_ids: list[UUID]
    errors: list[str]
