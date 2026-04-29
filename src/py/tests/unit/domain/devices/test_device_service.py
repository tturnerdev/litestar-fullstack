"""Unit tests for DeviceService business logic.

Tests service methods with mocked repositories. Focuses on:
- to_model_on_create() SIP defaults generation
- reboot_device() status update delegation
- reprovision_device() status update delegation
- set_device_lines() line replacement orchestration
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, Mock, MagicMock, patch
from uuid import uuid4

import pytest

from app.db.models._device_status import DeviceStatus
from app.domain.devices.services import DeviceService

pytestmark = [pytest.mark.anyio, pytest.mark.unit, pytest.mark.services]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_service() -> DeviceService:
    """Create a DeviceService with mocked base-class methods.

    Uses __new__ to skip __init__ (which requires a real session),
    then patches the inherited methods as AsyncMocks.
    """
    svc = DeviceService.__new__(DeviceService)
    svc.create = AsyncMock()
    svc.update = AsyncMock()
    svc.list = AsyncMock(return_value=[])
    svc.get = AsyncMock()
    svc.delete = AsyncMock()
    svc.count = AsyncMock(return_value=0)

    # Mock the repository via the internal attribute (the property is read-only)
    mock_repo = MagicMock()
    mock_repo.session = MagicMock()
    svc._repository_instance = mock_repo
    return svc


def _make_device(**overrides) -> Mock:
    """Build a mock Device instance with sensible defaults."""
    defaults = {
        "id": uuid4(),
        "user_id": uuid4(),
        "team_id": None,
        "name": "Desk Phone",
        "device_type": "desk_phone",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "device_model": "T54W",
        "manufacturer": "Yealink",
        "firmware_version": "96.86.0.80",
        "ip_address": "192.168.1.100",
        "sip_username": "dev_abc123",
        "sip_server": "sip.default.local",
        "status": DeviceStatus.ONLINE,
        "is_active": True,
        "last_seen_at": datetime.now(UTC),
        "provisioned_at": datetime.now(UTC),
        "config_json": None,
    }
    defaults.update(overrides)
    device = Mock()
    for k, v in defaults.items():
        setattr(device, k, v)
    return device


def _make_line(**overrides) -> Mock:
    """Build a mock DeviceLineAssignment instance."""
    defaults = {
        "id": uuid4(),
        "device_id": uuid4(),
        "line_number": 1,
        "extension_id": None,
        "label": "Line 1",
        "line_type": "private",
        "is_active": True,
    }
    defaults.update(overrides)
    line = Mock()
    for k, v in defaults.items():
        setattr(line, k, v)
    return line


# ---------------------------------------------------------------------------
# to_model_on_create
# ---------------------------------------------------------------------------


class TestToModelOnCreate:
    """Tests for DeviceService.to_model_on_create."""

    async def test_generates_sip_username_when_missing(self) -> None:
        """When sip_username is not provided, auto-generate one."""
        service = _make_service()
        data = {
            "name": "New Phone",
            "user_id": uuid4(),
            "device_type": "desk_phone",
        }

        result = await service.to_model_on_create(data)

        assert result["sip_username"].startswith("dev_")
        assert len(result["sip_username"]) == 20  # "dev_" + 16 hex chars

    async def test_preserves_provided_sip_username(self) -> None:
        """When sip_username is explicitly provided, keep it."""
        service = _make_service()
        data = {
            "name": "New Phone",
            "user_id": uuid4(),
            "device_type": "desk_phone",
            "sip_username": "custom_user",
        }

        result = await service.to_model_on_create(data)

        assert result["sip_username"] == "custom_user"

    async def test_generates_sip_server_when_missing(self) -> None:
        """When sip_server is not provided, set default."""
        service = _make_service()
        data = {
            "name": "New Phone",
            "user_id": uuid4(),
            "device_type": "desk_phone",
        }

        result = await service.to_model_on_create(data)

        assert result["sip_server"] == "sip.default.local"

    async def test_preserves_provided_sip_server(self) -> None:
        """When sip_server is explicitly provided, keep it."""
        service = _make_service()
        data = {
            "name": "New Phone",
            "user_id": uuid4(),
            "device_type": "desk_phone",
            "sip_server": "sip.custom.example.com",
        }

        result = await service.to_model_on_create(data)

        assert result["sip_server"] == "sip.custom.example.com"

    async def test_generates_unique_sip_usernames(self) -> None:
        """Two consecutive calls should generate different SIP usernames."""
        service = _make_service()
        data1 = {"name": "Phone 1", "user_id": uuid4(), "device_type": "desk_phone"}
        data2 = {"name": "Phone 2", "user_id": uuid4(), "device_type": "desk_phone"}

        result1 = await service.to_model_on_create(data1)
        result2 = await service.to_model_on_create(data2)

        assert result1["sip_username"] != result2["sip_username"]

    async def test_empty_string_sip_username_treated_as_missing(self) -> None:
        """An empty string sip_username is falsy and should be replaced."""
        service = _make_service()
        data = {
            "name": "Phone",
            "user_id": uuid4(),
            "device_type": "desk_phone",
            "sip_username": "",
        }

        result = await service.to_model_on_create(data)

        assert result["sip_username"].startswith("dev_")


# ---------------------------------------------------------------------------
# reboot_device
# ---------------------------------------------------------------------------


class TestRebootDevice:
    """Tests for DeviceService.reboot_device."""

    async def test_reboot_sets_rebooting_status(self) -> None:
        """Verify reboot_device calls update with REBOOTING status."""
        service = _make_service()
        device_id = uuid4()
        expected = _make_device(id=device_id, status=DeviceStatus.REBOOTING)
        service.update = AsyncMock(return_value=expected)

        result = await service.reboot_device(device_id=device_id)

        service.update.assert_awaited_once_with(
            item_id=device_id,
            data={"status": DeviceStatus.REBOOTING},
        )
        assert result is expected

    async def test_reboot_returns_device(self) -> None:
        """Verify the return value comes from update."""
        service = _make_service()
        device_id = uuid4()
        expected = _make_device(id=device_id)
        service.update = AsyncMock(return_value=expected)

        result = await service.reboot_device(device_id=device_id)

        assert result is expected


# ---------------------------------------------------------------------------
# reprovision_device
# ---------------------------------------------------------------------------


class TestReprovisionDevice:
    """Tests for DeviceService.reprovision_device."""

    async def test_reprovision_sets_provisioning_status(self) -> None:
        """Verify reprovision_device calls update with PROVISIONING status."""
        service = _make_service()
        device_id = uuid4()
        expected = _make_device(id=device_id, status=DeviceStatus.PROVISIONING)
        service.update = AsyncMock(return_value=expected)

        result = await service.reprovision_device(device_id=device_id)

        service.update.assert_awaited_once_with(
            item_id=device_id,
            data={"status": DeviceStatus.PROVISIONING},
        )
        assert result is expected

    async def test_reprovision_returns_device(self) -> None:
        """Verify the return value comes from update."""
        service = _make_service()
        device_id = uuid4()
        expected = _make_device(id=device_id)
        service.update = AsyncMock(return_value=expected)

        result = await service.reprovision_device(device_id=device_id)

        assert result is expected


# ---------------------------------------------------------------------------
# set_device_lines
# ---------------------------------------------------------------------------


class TestSetDeviceLines:
    """Tests for DeviceService.set_device_lines."""

    async def test_replaces_existing_lines_with_new_ones(self) -> None:
        """Verify existing lines are deleted and new ones created."""
        service = _make_service()
        device_id = uuid4()
        expected_device = _make_device(id=device_id)

        existing_lines = [_make_line(device_id=device_id, line_number=i) for i in range(1, 3)]

        new_lines_data = [
            {"line_number": 1, "label": "Main", "line_type": "private"},
            {"line_number": 2, "label": "Shared", "line_type": "shared"},
            {"line_number": 3, "label": "Park", "line_type": "private"},
        ]

        with patch(
            "app.domain.devices.services._device.DeviceLineAssignmentService",
        ) as MockLineSvc:
            line_svc_instance = MagicMock()
            line_svc_instance.list = AsyncMock(return_value=existing_lines)
            line_svc_instance.delete = AsyncMock()
            line_svc_instance.create = AsyncMock()
            MockLineSvc.return_value = line_svc_instance
            service.get = AsyncMock(return_value=expected_device)

            result = await service.set_device_lines(
                device_id=device_id,
                lines_data=new_lines_data,
            )

        # Should delete each existing line
        assert line_svc_instance.delete.await_count == 2
        # Should create each new line
        assert line_svc_instance.create.await_count == 3
        # Verify device_id is injected into each line data
        for call in line_svc_instance.create.call_args_list:
            assert call[0][0]["device_id"] == device_id
        # Should return the refreshed device
        assert result is expected_device

    async def test_replaces_with_empty_list(self) -> None:
        """Verify clearing all lines works."""
        service = _make_service()
        device_id = uuid4()
        expected_device = _make_device(id=device_id)

        existing_lines = [_make_line(device_id=device_id)]

        with patch(
            "app.domain.devices.services._device.DeviceLineAssignmentService",
        ) as MockLineSvc:
            line_svc_instance = MagicMock()
            line_svc_instance.list = AsyncMock(return_value=existing_lines)
            line_svc_instance.delete = AsyncMock()
            line_svc_instance.create = AsyncMock()
            MockLineSvc.return_value = line_svc_instance
            service.get = AsyncMock(return_value=expected_device)

            result = await service.set_device_lines(
                device_id=device_id,
                lines_data=[],
            )

        # Should delete existing lines
        assert line_svc_instance.delete.await_count == 1
        # Should not create any lines
        line_svc_instance.create.assert_not_awaited()
        assert result is expected_device

    async def test_no_existing_lines_creates_new(self) -> None:
        """Verify creating lines when none exist."""
        service = _make_service()
        device_id = uuid4()
        expected_device = _make_device(id=device_id)

        new_lines_data = [
            {"line_number": 1, "label": "Line 1", "line_type": "private"},
        ]

        with patch(
            "app.domain.devices.services._device.DeviceLineAssignmentService",
        ) as MockLineSvc:
            line_svc_instance = MagicMock()
            line_svc_instance.list = AsyncMock(return_value=[])
            line_svc_instance.delete = AsyncMock()
            line_svc_instance.create = AsyncMock()
            MockLineSvc.return_value = line_svc_instance
            service.get = AsyncMock(return_value=expected_device)

            result = await service.set_device_lines(
                device_id=device_id,
                lines_data=new_lines_data,
            )

        # No deletions
        line_svc_instance.delete.assert_not_awaited()
        # One creation
        line_svc_instance.create.assert_awaited_once()
        assert result is expected_device

    async def test_set_device_lines_passes_session_to_line_service(self) -> None:
        """Verify the DeviceLineAssignmentService gets the same session."""
        service = _make_service()
        device_id = uuid4()

        with patch(
            "app.domain.devices.services._device.DeviceLineAssignmentService",
        ) as MockLineSvc:
            line_svc_instance = MagicMock()
            line_svc_instance.list = AsyncMock(return_value=[])
            line_svc_instance.delete = AsyncMock()
            line_svc_instance.create = AsyncMock()
            MockLineSvc.return_value = line_svc_instance
            service.get = AsyncMock(return_value=_make_device(id=device_id))

            await service.set_device_lines(device_id=device_id, lines_data=[])

        MockLineSvc.assert_called_once_with(session=service.repository.session)

    async def test_set_device_lines_returns_refreshed_device(self) -> None:
        """Verify get() is called with device_id to return fresh state."""
        service = _make_service()
        device_id = uuid4()
        fresh_device = _make_device(id=device_id)

        with patch(
            "app.domain.devices.services._device.DeviceLineAssignmentService",
        ) as MockLineSvc:
            line_svc_instance = MagicMock()
            line_svc_instance.list = AsyncMock(return_value=[])
            line_svc_instance.delete = AsyncMock()
            line_svc_instance.create = AsyncMock()
            MockLineSvc.return_value = line_svc_instance
            service.get = AsyncMock(return_value=fresh_device)

            result = await service.set_device_lines(device_id=device_id, lines_data=[])

        service.get.assert_awaited_once_with(device_id)
        assert result is fresh_device
