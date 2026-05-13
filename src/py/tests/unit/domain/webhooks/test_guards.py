"""Tests for webhook domain guards."""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from litestar.exceptions import PermissionDeniedException

from app.domain.webhooks.guards import requires_webhook_ownership
from app.lib import constants


def _make_connection(*, is_superuser: bool = False, roles: list[Mock] | None = None) -> Mock:
    connection = Mock()
    connection.user.is_superuser = is_superuser
    connection.user.roles = roles if roles is not None else []
    return connection


def _make_role(role_name: str) -> Mock:
    role = Mock()
    role.role_name = role_name
    return role


class TestRequiresWebhookOwnership:
    def test_superuser_passes(self) -> None:
        requires_webhook_ownership(_make_connection(is_superuser=True), Mock())

    def test_superuser_role_passes(self) -> None:
        role = _make_role(constants.SUPERUSER_ACCESS_ROLE)
        requires_webhook_ownership(_make_connection(roles=[role]), Mock())

    def test_regular_user_denied(self) -> None:
        with pytest.raises(PermissionDeniedException, match="webhook"):
            requires_webhook_ownership(_make_connection(), Mock())
