"""Bulk import schemas for phone numbers."""

from uuid import UUID

from app.lib.schema import CamelizedBaseStruct


class BulkImportRowPreview(CamelizedBaseStruct, kw_only=True):
    row_number: int
    number: str
    user_id: str
    label: str | None = None
    number_type: str = "local"
    caller_id_name: str | None = None
    is_duplicate: bool = False


class BulkImportRowError(CamelizedBaseStruct, kw_only=True):
    row_number: int
    errors: list[str]


class BulkImportPhoneNumberPreview(CamelizedBaseStruct, kw_only=True):
    valid_rows: list[BulkImportRowPreview]
    error_rows: list[BulkImportRowError]
    duplicate_numbers: list[str]
    total_rows: int
    valid_count: int
    error_count: int
    duplicate_count: int


class BulkImportRowData(CamelizedBaseStruct, kw_only=True):
    number: str
    user_id: UUID
    label: str | None = None
    number_type: str = "local"
    caller_id_name: str | None = None
    team_id: UUID | None = None


class BulkImportPhoneNumberRequest(CamelizedBaseStruct, kw_only=True):
    rows: list[BulkImportRowData]
    skip_duplicates: bool = True


class BulkImportPhoneNumberResult(CamelizedBaseStruct, kw_only=True):
    created_count: int
    skipped_count: int
    error_count: int
    created_ids: list[UUID]
    errors: list[str]
