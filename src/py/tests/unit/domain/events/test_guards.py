"""Tests for events domain guards."""

from __future__ import annotations

from unittest.mock import Mock

from app.domain.events.guards import requires_active_session


class TestRequiresActiveSession:
    def test_passes(self) -> None:
        requires_active_session(Mock(), Mock())
