"""Admin Bulk Import Controller — CSV upload for devices and extensions."""

from __future__ import annotations

import csv
import io
import logging
import re
from typing import TYPE_CHECKING, Annotated, Any

from litestar import Controller, post
from litestar.datastructures import UploadFile
from litestar.di import Provide
from litestar.enums import RequestEncodingType
from litestar.exceptions import HTTPException
from litestar.params import Body

from app.db import models as m
from app.domain.accounts.guards import requires_superuser
from app.domain.admin.deps import provide_audit_log_service
from app.domain.admin.schemas import BulkImportPreview, BulkImportPreviewRow, BulkImportResult
from app.domain.devices.services import DeviceService
from app.domain.voice.services import ExtensionService
from app.lib.deps import create_service_dependencies

if TYPE_CHECKING:
    from litestar import Request
    from litestar.security.jwt import Token

    from app.domain.admin.services import AuditLogService

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")

_DEVICE_ALL_FIELDS = {
    "name",
    "mac_address",
    "model",
    "manufacturer",
    "device_type",
    "sip_username",
    "sip_password",
    "ip_address",
}

_EXTENSION_ALL_FIELDS = {"extension_number", "display_name"}

_MAX_CSV_SIZE = 5 * 1024 * 1024  # 5 MB
_MAX_CSV_ROWS = 5000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_mac(raw: str) -> str:
    """Normalize a MAC address to colon-separated uppercase format."""
    cleaned = re.sub(r"[:\-.]", "", raw.strip().upper())
    if len(cleaned) != 12:
        return raw.strip()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def _parse_csv(content: str, allowed_fields: set[str]) -> list[dict[str, str]]:
    """Parse CSV text into a list of row dicts, filtering to allowed columns."""
    reader = csv.DictReader(io.StringIO(content))
    rows: list[dict[str, str]] = []
    for row in reader:
        clean: dict[str, str] = {}
        for key, value in row.items():
            if key is None:
                continue
            normalized_key = key.strip().lower().replace(" ", "_")
            if normalized_key in allowed_fields and value is not None:
                clean[normalized_key] = value.strip()
        rows.append(clean)
    return rows


def _validate_device_row(row: dict[str, str]) -> list[str]:
    """Validate a single device CSV row. Returns a list of error messages."""
    errors: list[str] = []

    if not row.get("name"):
        errors.append("'name' is required")

    mac = row.get("mac_address", "").strip()
    if mac and not _MAC_RE.match(_normalize_mac(mac)):
        errors.append(f"Invalid MAC address format: {mac}")

    device_type = row.get("device_type", "").strip().lower()
    if device_type:
        valid_types = {dt.value for dt in m.DeviceType}
        if device_type not in valid_types:
            errors.append(f"Invalid device_type: {device_type}. Valid: {', '.join(sorted(valid_types))}")

    return errors


def _validate_extension_row(row: dict[str, str]) -> list[str]:
    """Validate a single extension CSV row. Returns a list of error messages."""
    errors: list[str] = []

    if not row.get("extension_number"):
        errors.append("'extension_number' is required")
    if not row.get("display_name"):
        errors.append("'display_name' is required")

    ext_num = row.get("extension_number", "").strip()
    if ext_num and not ext_num.isdigit():
        errors.append(f"Extension number must be numeric: {ext_num}")

    return errors


async def _read_upload_csv(data: dict[str, Any]) -> str:
    """Extract and validate the uploaded CSV file from multipart data.

    Args:
        data: The parsed multipart form data dictionary.

    Returns:
        The decoded CSV text content.

    Raises:
        HTTPException: If the file is missing, too large, or not a CSV file.
    """
    file = data.get("file")
    if not isinstance(file, UploadFile) or not file.filename:
        raise HTTPException(status_code=400, detail="A CSV file is required. Upload a file with the field name 'file'.")

    if file.filename and not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are accepted.")

    raw = await file.read()
    if len(raw) > _MAX_CSV_SIZE:
        raise HTTPException(status_code=400, detail=f"File exceeds maximum size of {_MAX_CSV_SIZE // (1024 * 1024)} MB.")

    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            return raw.decode("latin-1")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail="Unable to decode the CSV file. Please use UTF-8 encoding.") from exc


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------


class AdminBulkImportController(Controller):
    """Bulk CSV import endpoints for devices and extensions."""

    tags = ["Admin"]
    path = "/api/admin/bulk-import"
    guards = [requires_superuser]
    dependencies = create_service_dependencies(
        DeviceService,
        key="device_service",
        filters={},
    ) | {
        "audit_service": Provide(provide_audit_log_service),
    }

    # ----- Device Preview -----

    @post(
        operation_id="AdminPreviewDeviceImport",
        path="/preview/devices",
    )
    async def preview_device_import(
        self,
        device_service: DeviceService,
        data: Annotated[dict[str, Any], Body(media_type=RequestEncodingType.MULTI_PART)],
    ) -> BulkImportPreview:
        """Preview a device CSV import without persisting any changes.

        Parses and validates each row, checks for duplicate MAC addresses,
        and returns the preview result.

        Args:
            device_service: Device service for duplicate checks.
            data: Multipart form data containing the CSV file.

        Returns:
            Preview of the import with row-level status and errors.
        """
        content = await _read_upload_csv(data)
        rows = _parse_csv(content, _DEVICE_ALL_FIELDS)

        if not rows:
            raise HTTPException(status_code=400, detail="CSV file is empty or has no valid rows.")

        if len(rows) > _MAX_CSV_ROWS:
            raise HTTPException(status_code=400, detail=f"CSV exceeds maximum of {_MAX_CSV_ROWS} rows.")

        # Build a set of existing MAC addresses for duplicate detection
        existing_devices = await device_service.list()
        existing_macs: set[str] = set()
        for d in existing_devices:
            if d.mac_address:
                existing_macs.add(d.mac_address.upper())

        seen_macs_in_file: set[str] = set()
        preview_rows: list[BulkImportPreviewRow] = []

        for idx, row in enumerate(rows, start=2):  # row 1 is the header
            errors = _validate_device_row(row)
            mac = row.get("mac_address", "").strip()
            normalized_mac = _normalize_mac(mac) if mac else ""

            action = "create"
            if normalized_mac:
                if normalized_mac.upper() in seen_macs_in_file:
                    errors.append(f"Duplicate MAC address in file: {normalized_mac}")
                    action = "skip"
                elif normalized_mac.upper() in existing_macs:
                    action = "update"
                seen_macs_in_file.add(normalized_mac.upper())

            if errors:
                action = "skip"

            preview_rows.append(
                BulkImportPreviewRow(
                    row_number=idx,
                    action=action,
                    data=dict(row),
                    errors=errors,
                )
            )

        error_count = sum(1 for r in preview_rows if r.errors)

        return BulkImportPreview(
            total_rows=len(preview_rows),
            valid_rows=len(preview_rows) - error_count,
            error_rows=error_count,
            rows=preview_rows,
        )

    # ----- Device Import -----

    @post(
        operation_id="AdminImportDevices",
        path="/devices",
    )
    async def import_devices(
        self,
        request: Request[m.User, Token, Any],
        device_service: DeviceService,
        audit_service: AuditLogService,
        data: Annotated[dict[str, Any], Body(media_type=RequestEncodingType.MULTI_PART)],
    ) -> BulkImportResult:
        """Import devices from a CSV file.

        Parses, validates, and creates or updates devices in bulk.

        Args:
            request: HTTP request with authenticated superuser.
            device_service: Device service for CRUD operations.
            audit_service: Audit log service for recording the import.
            data: Multipart form data containing the CSV file.

        Returns:
            Import result with counts and any errors encountered.
        """
        content = await _read_upload_csv(data)
        rows = _parse_csv(content, _DEVICE_ALL_FIELDS)

        if not rows:
            raise HTTPException(status_code=400, detail="CSV file is empty or has no valid rows.")

        if len(rows) > _MAX_CSV_ROWS:
            raise HTTPException(status_code=400, detail=f"CSV exceeds maximum of {_MAX_CSV_ROWS} rows.")

        # Index existing devices by MAC for upsert logic
        existing_devices = await device_service.list()
        mac_to_device: dict[str, m.Device] = {}
        for d in existing_devices:
            if d.mac_address:
                mac_to_device[d.mac_address.upper()] = d

        created = 0
        updated = 0
        skipped = 0
        errors: list[str] = []

        for idx, row in enumerate(rows, start=2):
            row_errors = _validate_device_row(row)
            if row_errors:
                errors.append(f"Row {idx}: {'; '.join(row_errors)}")
                skipped += 1
                continue

            mac = row.get("mac_address", "").strip()
            normalized_mac = _normalize_mac(mac) if mac else ""

            device_type = row.get("device_type", "").strip().lower() or "other"

            device_data: dict[str, Any] = {
                "name": row["name"],
                "device_type": device_type,
                "user_id": request.user.id,
            }

            if normalized_mac:
                device_data["mac_address"] = normalized_mac
            if row.get("model"):
                device_data["device_model"] = row["model"]
            if row.get("manufacturer"):
                device_data["manufacturer"] = row["manufacturer"]
            if row.get("sip_username"):
                device_data["sip_username"] = row["sip_username"]
            if row.get("ip_address"):
                device_data["ip_address"] = row["ip_address"]

            try:
                if normalized_mac and normalized_mac.upper() in mac_to_device:
                    existing = mac_to_device[normalized_mac.upper()]
                    await device_service.update(data=device_data, item_id=existing.id)
                    updated += 1
                else:
                    await device_service.create(data=device_data)
                    created += 1
            except Exception as exc:
                logger.exception("Bulk import error at row %d", idx)
                errors.append(f"Row {idx}: {exc!s}")
                skipped += 1

        await audit_service.log_action(
            action="admin.bulk_import.devices",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="device",
            details={
                "total_rows": len(rows),
                "created": created,
                "updated": updated,
                "skipped": skipped,
                "error_count": len(errors),
            },
            request=request,
        )

        return BulkImportResult(
            created=created,
            updated=updated,
            skipped=skipped,
            errors=errors,
        )

    # ----- Extension Preview -----

    @post(
        operation_id="AdminPreviewExtensionImport",
        path="/preview/extensions",
    )
    async def preview_extension_import(
        self,
        device_service: DeviceService,
        data: Annotated[dict[str, Any], Body(media_type=RequestEncodingType.MULTI_PART)],
    ) -> BulkImportPreview:
        """Preview an extension CSV import without persisting any changes.

        Args:
            device_service: Device service (used to obtain shared DB session).
            data: Multipart form data containing the CSV file.

        Returns:
            Preview of the import with row-level status and errors.
        """
        extension_service = ExtensionService(session=device_service.repository.session)
        content = await _read_upload_csv(data)
        rows = _parse_csv(content, _EXTENSION_ALL_FIELDS)

        if not rows:
            raise HTTPException(status_code=400, detail="CSV file is empty or has no valid rows.")

        if len(rows) > _MAX_CSV_ROWS:
            raise HTTPException(status_code=400, detail=f"CSV exceeds maximum of {_MAX_CSV_ROWS} rows.")

        existing_extensions = await extension_service.list()
        existing_numbers: set[str] = {e.extension_number for e in existing_extensions}

        seen_numbers_in_file: set[str] = set()
        preview_rows: list[BulkImportPreviewRow] = []

        for idx, row in enumerate(rows, start=2):
            errors = _validate_extension_row(row)
            ext_num = row.get("extension_number", "").strip()

            action = "create"
            if ext_num:
                if ext_num in seen_numbers_in_file:
                    errors.append(f"Duplicate extension number in file: {ext_num}")
                    action = "skip"
                elif ext_num in existing_numbers:
                    action = "update"
                seen_numbers_in_file.add(ext_num)

            if errors:
                action = "skip"

            preview_rows.append(
                BulkImportPreviewRow(
                    row_number=idx,
                    action=action,
                    data=dict(row),
                    errors=errors,
                )
            )

        error_count = sum(1 for r in preview_rows if r.errors)

        return BulkImportPreview(
            total_rows=len(preview_rows),
            valid_rows=len(preview_rows) - error_count,
            error_rows=error_count,
            rows=preview_rows,
        )

    # ----- Extension Import -----

    @post(
        operation_id="AdminImportExtensions",
        path="/extensions",
    )
    async def import_extensions(
        self,
        request: Request[m.User, Token, Any],
        device_service: DeviceService,
        audit_service: AuditLogService,
        data: Annotated[dict[str, Any], Body(media_type=RequestEncodingType.MULTI_PART)],
    ) -> BulkImportResult:
        """Import extensions from a CSV file.

        Parses, validates, and creates or updates extensions in bulk.

        Args:
            request: HTTP request with authenticated superuser.
            device_service: Device service (used to obtain shared session).
            audit_service: Audit log service for recording the import.
            data: Multipart form data containing the CSV file.

        Returns:
            Import result with counts and any errors encountered.
        """
        extension_service = ExtensionService(session=device_service.repository.session)
        content = await _read_upload_csv(data)
        rows = _parse_csv(content, _EXTENSION_ALL_FIELDS)

        if not rows:
            raise HTTPException(status_code=400, detail="CSV file is empty or has no valid rows.")

        if len(rows) > _MAX_CSV_ROWS:
            raise HTTPException(status_code=400, detail=f"CSV exceeds maximum of {_MAX_CSV_ROWS} rows.")

        # Index existing extensions by number for upsert logic
        existing_extensions = await extension_service.list()
        number_to_ext: dict[str, m.Extension] = {e.extension_number: e for e in existing_extensions}

        created = 0
        updated = 0
        skipped = 0
        errors: list[str] = []

        for idx, row in enumerate(rows, start=2):
            row_errors = _validate_extension_row(row)
            if row_errors:
                errors.append(f"Row {idx}: {'; '.join(row_errors)}")
                skipped += 1
                continue

            ext_num = row["extension_number"].strip()
            display_name = row["display_name"].strip()

            try:
                if ext_num in number_to_ext:
                    existing = number_to_ext[ext_num]
                    await extension_service.update(
                        data={"display_name": display_name},
                        item_id=existing.id,
                    )
                    updated += 1
                else:
                    await extension_service.create(
                        data={
                            "extension_number": ext_num,
                            "display_name": display_name,
                            "user_id": request.user.id,
                        }
                    )
                    created += 1
            except Exception as exc:
                logger.exception("Bulk import error at row %d", idx)
                errors.append(f"Row {idx}: {exc!s}")
                skipped += 1

        await audit_service.log_action(
            action="admin.bulk_import.extensions",
            actor_id=request.user.id,
            actor_email=request.user.email,
            actor_name=request.user.name,
            target_type="extension",
            details={
                "total_rows": len(rows),
                "created": created,
                "updated": updated,
                "skipped": skipped,
                "error_count": len(errors),
            },
            request=request,
        )

        return BulkImportResult(
            created=created,
            updated=updated,
            skipped=skipped,
            errors=errors,
        )

