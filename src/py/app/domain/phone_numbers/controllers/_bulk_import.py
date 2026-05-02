"""Admin bulk import controller for phone numbers."""

from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING, Any

from litestar import Controller, post
from litestar.di import Provide
from litestar.enums import RequestEncodingType
from litestar.params import Body

from app.db import models as m
from app.domain.accounts.guards import requires_superuser
from app.domain.admin.deps import provide_audit_log_service
from app.domain.phone_numbers.deps import provide_phone_number_service
from app.domain.phone_numbers.schemas import (
    BulkImportPhoneNumberPreview,
    BulkImportPhoneNumberRequest,
    BulkImportPhoneNumberResult,
    BulkImportRowError,
    BulkImportRowPreview,
)
from app.domain.phone_numbers.services._phone_number import (
    normalize_phone_number,
    validate_phone_row,
)

if TYPE_CHECKING:
    from litestar import Request
    from litestar.datastructures import UploadFile
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService
    from app.domain.phone_numbers.services import PhoneNumberService

# CSV field names that are accepted (lowercase, underscore-separated)
_EXPECTED_HEADERS = {
    "number",
    "user_id",
    "label",
    "number_type",
    "caller_id_name",
    "team_id",
}

MAX_IMPORT_ROWS = 1000


class AdminPhoneNumberBulkImportController(Controller):
    """Admin endpoints for bulk importing phone numbers via CSV."""

    tags = ["Admin", "Phone Numbers"]
    path = "/api/admin/phone-numbers/bulk-import"
    guards = [requires_superuser]
    dependencies = {
        "phone_number_service": Provide(provide_phone_number_service),
        "audit_service": Provide(provide_audit_log_service),
    }

    @post(
        operation_id="AdminPreviewPhoneNumberBulkImport",
        path="/preview",
    )
    async def preview_import(
        self,
        request: Request[m.User, Token, Any],
        phone_number_service: PhoneNumberService,
        data: UploadFile = Body(media_type=RequestEncodingType.MULTI_PART),
    ) -> BulkImportPhoneNumberPreview:
        """Parse and validate a CSV file, returning a preview of what will be imported.

        Accepts a CSV file with headers matching phone number fields.
        Returns validated rows, errors, and duplicate detection results.

        Args:
            request: Request with authenticated superuser.
            phone_number_service: Phone number service.
            data: Uploaded CSV file.

        Returns:
            Preview with valid rows, errors, and duplicates.
        """
        content = await data.read()
        text = content.decode("utf-8-sig")  # Handle BOM from Excel

        reader = csv.DictReader(io.StringIO(text))
        if reader.fieldnames is None:
            return BulkImportPhoneNumberPreview(
                valid_rows=[],
                error_rows=[BulkImportRowError(row_number=0, errors=["CSV file is empty or has no headers"])],
                duplicate_numbers=[],
                total_rows=0,
                valid_count=0,
                error_count=1,
                duplicate_count=0,
            )

        # Normalize header names: strip whitespace, lowercase, replace spaces with underscores
        normalized_fieldnames = [h.strip().lower().replace(" ", "_") for h in reader.fieldnames]

        # First pass: validate all rows and collect data
        validated_data: list[tuple[int, dict[str, Any]]] = []
        error_rows: list[BulkImportRowError] = []
        seen_in_file: set[str] = set()

        row_count = 0
        for row_idx, raw_row in enumerate(reader, start=1):
            if row_idx > MAX_IMPORT_ROWS:
                error_rows.append(
                    BulkImportRowError(
                        row_number=row_idx,
                        errors=[f"Maximum of {MAX_IMPORT_ROWS} rows exceeded. Truncated."],
                    )
                )
                break

            # Re-key with normalized headers
            row = {normalized_fieldnames[i]: v for i, (_, v) in enumerate(raw_row.items()) if i < len(normalized_fieldnames)}

            row_count += 1
            validated, errors = validate_phone_row(row, row_idx)

            if errors:
                error_rows.append(BulkImportRowError(row_number=row_idx, errors=errors))
                continue

            if validated is None:
                continue

            # Check for in-file duplicates
            number = validated["number"]
            if number in seen_in_file:
                error_rows.append(
                    BulkImportRowError(
                        row_number=row_idx,
                        errors=[f"Row {row_idx}: Duplicate number '{number}' within the same file"],
                    )
                )
            else:
                seen_in_file.add(number)
                validated_data.append((row_idx, validated))

        # Check against existing database records
        numbers_to_check = [v["number"] for _, v in validated_data]
        existing_numbers = await phone_number_service.check_duplicates(numbers_to_check)
        duplicate_numbers = sorted(existing_numbers)

        # Build preview rows with duplicate flag already set
        valid_rows: list[BulkImportRowPreview] = [
            BulkImportRowPreview(
                row_number=row_idx,
                number=validated["number"],
                user_id=validated.get("user_id", ""),
                label=validated.get("label"),
                number_type=validated.get("number_type", "local"),
                caller_id_name=validated.get("caller_id_name"),
                is_duplicate=validated["number"] in existing_numbers,
            )
            for row_idx, validated in validated_data
        ]

        return BulkImportPhoneNumberPreview(
            valid_rows=valid_rows,
            error_rows=error_rows,
            duplicate_numbers=duplicate_numbers,
            total_rows=row_count,
            valid_count=len([r for r in valid_rows if not r.is_duplicate]),
            error_count=len(error_rows),
            duplicate_count=len(duplicate_numbers),
        )

    @post(
        operation_id="AdminExecutePhoneNumberBulkImport",
        path="/execute",
    )
    async def execute_import(
        self,
        request: Request[m.User, Token, Any],
        phone_number_service: PhoneNumberService,
        audit_service: AuditLogService,
        data: BulkImportPhoneNumberRequest,
    ) -> BulkImportPhoneNumberResult:
        """Execute the bulk import of phone numbers.

        Takes the validated rows from preview and creates phone number records.

        Args:
            request: Request with authenticated superuser.
            phone_number_service: Phone number service.
            audit_service: Audit log service.
            data: Import request with validated rows.

        Returns:
            Result with created count, skipped count, and any errors.
        """
        if not data.rows:
            return BulkImportPhoneNumberResult(
                created_count=0,
                skipped_count=0,
                error_count=0,
                created_ids=[],
                errors=[],
            )

        # Normalize and validate each row
        to_create: list[dict[str, Any]] = []
        errors: list[str] = []
        numbers_seen: set[str] = set()

        for idx, row in enumerate(data.rows, start=1):
            try:
                normalized = normalize_phone_number(row.number)
            except ValueError as e:
                errors.append(f"Row {idx}: {e}")
                continue

            if normalized in numbers_seen:
                errors.append(f"Row {idx}: Duplicate number '{normalized}' in request")
                continue
            numbers_seen.add(normalized)

            to_create.append({
                "number": normalized,
                "user_id": row.user_id,
                "label": row.label,
                "number_type": row.number_type,
                "caller_id_name": row.caller_id_name,
                "team_id": row.team_id,
            })

        # Check for existing numbers in DB
        all_numbers = [item["number"] for item in to_create]
        existing = await phone_number_service.check_duplicates(all_numbers)

        skipped_count = 0
        final_create: list[dict[str, Any]] = []

        for item in to_create:
            if item["number"] in existing:
                if data.skip_duplicates:
                    skipped_count += 1
                else:
                    errors.append(f"Number '{item['number']}' already exists")
            else:
                final_create.append(item)

        # Bulk create
        created: list[m.PhoneNumber] = []
        if final_create:
            try:
                created = await phone_number_service.bulk_create(final_create)
            except Exception as e:
                errors.append(f"Database error during bulk create: {e}")

        # Audit log
        if created:
            await audit_service.log_action(
                action="admin.phone_number.bulk_import",
                actor_id=request.user.id,
                actor_email=request.user.email,
                target_type="phone_number",
                target_label=f"Bulk import: {len(created)} numbers",
                details={
                    "created_count": len(created),
                    "skipped_count": skipped_count,
                    "error_count": len(errors),
                },
                request=request,
            )

        return BulkImportPhoneNumberResult(
            created_count=len(created),
            skipped_count=skipped_count,
            error_count=len(errors),
            created_ids=[pn.id for pn in created],
            errors=errors,
        )
