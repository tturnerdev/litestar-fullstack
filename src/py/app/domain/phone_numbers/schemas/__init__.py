"""Phone numbers domain schemas."""

from app.domain.phone_numbers.schemas._bulk_import import (
    BulkImportPhoneNumberPreview,
    BulkImportPhoneNumberRequest,
    BulkImportPhoneNumberResult,
    BulkImportRowData,
    BulkImportRowError,
    BulkImportRowPreview,
)
from app.domain.phone_numbers.schemas._phone_number import (
    PhoneNumberCreate,
    PhoneNumberDetail,
    PhoneNumberList,
    PhoneNumberUpdate,
)

__all__ = (
    "BulkImportPhoneNumberPreview",
    "BulkImportPhoneNumberRequest",
    "BulkImportPhoneNumberResult",
    "BulkImportRowData",
    "BulkImportRowError",
    "BulkImportRowPreview",
    "PhoneNumberCreate",
    "PhoneNumberDetail",
    "PhoneNumberList",
    "PhoneNumberUpdate",
)
