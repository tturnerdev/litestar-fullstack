"""Phone number service for CRUD and bulk operations."""

from __future__ import annotations

import re
from typing import Any

from advanced_alchemy.extensions.litestar import repository, service

from app.db import models as m

_E164_PATTERN = re.compile(r"^\+[1-9]\d{1,14}$")
_DIGITS_ONLY = re.compile(r"\D")

VALID_NUMBER_TYPES = {"local", "toll_free", "international"}


def normalize_phone_number(raw: str) -> str:
    stripped = raw.strip()
    if not stripped:
        msg = "Phone number cannot be empty"
        raise ValueError(msg)

    has_plus = stripped.startswith("+")
    digits = _DIGITS_ONLY.sub("", stripped)

    if not digits:
        msg = f"No digits found in phone number: {raw}"
        raise ValueError(msg)

    if len(digits) == 10 and not has_plus:
        result = f"+1{digits}"
    elif has_plus:
        result = f"+{digits}"
    elif len(digits) == 11 and digits.startswith("1"):
        result = f"+{digits}"
    else:
        result = f"+{digits}"

    if not _E164_PATTERN.match(result):
        msg = f"Cannot normalize to valid E.164 format: {raw}"
        raise ValueError(msg)

    return result


def validate_phone_row(row: dict[str, str], row_index: int) -> tuple[dict[str, Any] | None, list[str]]:
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
        if len(label) > 100:
            errors.append(f"Row {row_index}: 'label' must be 100 characters or fewer")
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
        if len(caller_id_name) > 50:
            errors.append(f"Row {row_index}: 'caller_id_name' must be 50 characters or fewer")
        else:
            data["caller_id_name"] = caller_id_name

    team_id = row.get("team_id", "").strip()
    if team_id:
        data["team_id"] = team_id

    if errors:
        return None, errors

    return data, []


class PhoneNumberService(service.SQLAlchemyAsyncRepositoryService[m.PhoneNumber]):

    class Repo(repository.SQLAlchemyAsyncRepository[m.PhoneNumber]):
        model_type = m.PhoneNumber

    repository_type = Repo
    match_fields = ["number"]

    async def check_duplicates(self, numbers: list[str]) -> set[str]:
        if not numbers:
            return set()
        existing = await self.list(m.PhoneNumber.number.in_(numbers))
        return {pn.number for pn in existing}

    async def bulk_create(self, items: list[dict[str, Any]]) -> list[m.PhoneNumber]:
        return list(await self.create_many(items, auto_commit=True))
