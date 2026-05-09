"""Phone number utilities and service re-export.

The canonical PhoneNumberService lives in ``app.domain.voice.services``.
This module re-exports it so that existing imports from
``app.domain.phone_numbers.services`` continue to work, and provides
module-level utility functions used by the bulk-import controller.
"""

from __future__ import annotations

import re
from typing import Any

from app.domain.voice.services._phone_number import PhoneNumberService

_E164_PATTERN = re.compile(r"^\+[1-9]\d{1,14}$")
_DIGITS_ONLY = re.compile(r"\D")

VALID_NUMBER_TYPES = {"local", "toll_free", "international"}

NANP_LOCAL_DIGITS = 10
NANP_FULL_DIGITS = 11
MAX_LABEL_LENGTH = 100
MAX_CALLER_ID_NAME_LENGTH = 50


def normalize_phone_number(raw: str) -> str:
    """Normalize a raw phone string to E.164 format.

    Args:
        raw: Raw phone number string.

    Returns:
        E.164 formatted phone number.

    Raises:
        ValueError: If the input cannot be normalized to valid E.164.
    """
    stripped = raw.strip()
    if not stripped:
        msg = "Phone number cannot be empty"
        raise ValueError(msg)

    has_plus = stripped.startswith("+")
    digits = _DIGITS_ONLY.sub("", stripped)

    if not digits:
        msg = f"No digits found in phone number: {raw}"
        raise ValueError(msg)

    if len(digits) == NANP_LOCAL_DIGITS and not has_plus:
        result = f"+1{digits}"
    elif has_plus or (len(digits) == NANP_FULL_DIGITS and digits.startswith("1")):
        result = f"+{digits}"
    else:
        result = f"+{digits}"

    if not _E164_PATTERN.match(result):
        msg = f"Cannot normalize to valid E.164 format: {raw}"
        raise ValueError(msg)

    return result


def validate_phone_row(row: dict[str, str], row_index: int) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate a single CSV row for phone number bulk import.

    Args:
        row: Dict of field name to value from CSV.
        row_index: 1-based row number for error messages.

    Returns:
        Tuple of (validated_data_dict_or_None, error_list).
    """
    errors: list[str] = []
    data: dict[str, Any] = {}

    raw_number = row.get("number", "").strip()
    if not raw_number:
        errors.append(f"Row {row_index}: 'number' is required")
    else:
        try:
            data["number"] = normalize_phone_number(raw_number)
        except ValueError as e:
            errors.append(f"Row {row_index}: {e}")

    user_id = row.get("user_id", "").strip()
    if not user_id:
        errors.append(f"Row {row_index}: 'user_id' is required")
    else:
        data["user_id"] = user_id

    label = row.get("label", "").strip()
    if label:
        if len(label) > MAX_LABEL_LENGTH:
            errors.append(f"Row {row_index}: 'label' must be {MAX_LABEL_LENGTH} characters or fewer")
        else:
            data["label"] = label

    number_type = row.get("number_type", "").strip().lower()
    if number_type:
        if number_type not in VALID_NUMBER_TYPES:
            errors.append(f"Row {row_index}: 'number_type' must be one of {', '.join(sorted(VALID_NUMBER_TYPES))}")
        else:
            data["number_type"] = number_type
    else:
        data["number_type"] = "local"

    caller_id_name = row.get("caller_id_name", "").strip()
    if caller_id_name:
        if len(caller_id_name) > MAX_CALLER_ID_NAME_LENGTH:
            errors.append(f"Row {row_index}: 'caller_id_name' must be {MAX_CALLER_ID_NAME_LENGTH} characters or fewer")
        else:
            data["caller_id_name"] = caller_id_name

    team_id = row.get("team_id", "").strip()
    if team_id:
        data["team_id"] = team_id

    if errors:
        return None, errors

    return data, []


__all__ = ("PhoneNumberService", "normalize_phone_number", "validate_phone_row")
