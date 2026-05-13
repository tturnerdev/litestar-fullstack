"""Tests for discovery state and caching."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.utils.domain._state import DiscoveryCache, DiscoveryState


class TestDiscoveryCache:
    def test_initial_state(self) -> None:
        cache = DiscoveryCache()
        assert cache.get() is None
        assert cache.is_cached(["pkg1"]) is False

    def test_set_and_get(self) -> None:
        cache = DiscoveryCache()
        mock_ctrl = MagicMock()
        cache.set([mock_ctrl], ["pkg1"])  # type: ignore[arg-type]
        assert cache.get() == [mock_ctrl]
        assert cache.is_cached(["pkg1"]) is True

    def test_is_cached_subset(self) -> None:
        cache = DiscoveryCache()
        mock_ctrl = MagicMock()
        cache.set([mock_ctrl], ["pkg1", "pkg2"])  # type: ignore[arg-type]
        assert cache.is_cached(["pkg1"]) is True
        assert cache.is_cached(["pkg2"]) is True
        assert cache.is_cached(["pkg1", "pkg2"]) is True

    def test_is_cached_different_package(self) -> None:
        cache = DiscoveryCache()
        mock_ctrl = MagicMock()
        cache.set([mock_ctrl], ["pkg1"])  # type: ignore[arg-type]
        assert cache.is_cached(["pkg2"]) is False

    def test_clear(self) -> None:
        cache = DiscoveryCache()
        mock_ctrl = MagicMock()
        cache.set([mock_ctrl], ["pkg1"])  # type: ignore[arg-type]
        cache.clear()
        assert cache.get() is None
        assert cache.is_cached(["pkg1"]) is False

    def test_set_accumulates_packages(self) -> None:
        cache = DiscoveryCache()
        mock_ctrl = MagicMock()
        cache.set([mock_ctrl], ["pkg1"])  # type: ignore[arg-type]
        cache.set([mock_ctrl], ["pkg2"])  # type: ignore[arg-type]
        assert cache.is_cached(["pkg1"]) is True
        assert cache.is_cached(["pkg2"]) is True


class TestDiscoveryState:
    def setup_method(self) -> None:
        DiscoveryState.reset()

    def test_reset(self) -> None:
        DiscoveryState.controller_count = 10
        DiscoveryState.signal_count = 5
        DiscoveryState.schema_count = 3
        DiscoveryState.service_count = 2
        DiscoveryState.repository_count = 1
        DiscoveryState.controllers_by_domain = {"test": ["Ctrl"]}
        DiscoveryState.logged_controllers = True
        DiscoveryState.reset()
        assert DiscoveryState.controller_count == 0
        assert DiscoveryState.signal_count == 0
        assert DiscoveryState.schema_count == 0
        assert DiscoveryState.service_count == 0
        assert DiscoveryState.repository_count == 0
        assert DiscoveryState.controllers_by_domain == {}
        assert DiscoveryState.logged_controllers is False

    def test_log_discovery_results(self) -> None:
        DiscoveryState.controller_count = 5
        DiscoveryState.service_count = 3
        DiscoveryState.controllers_by_domain = {"domain1": ["Ctrl1"]}

        with patch("app.utils.domain._state.logger") as mock_logger:
            DiscoveryState.log_discovery_results()
            mock_logger.info.assert_called_once()
            assert DiscoveryState.logged_controllers is True

    def test_log_not_repeated(self) -> None:
        DiscoveryState.controller_count = 5
        DiscoveryState.controllers_by_domain = {"d": ["C"]}

        with patch("app.utils.domain._state.logger") as mock_logger:
            DiscoveryState.log_discovery_results()
            mock_logger.reset_mock()
            DiscoveryState.log_discovery_results()
            mock_logger.info.assert_not_called()

    def test_log_skips_zero_controllers(self) -> None:
        with patch("app.utils.domain._state.logger") as mock_logger:
            DiscoveryState.log_discovery_results()
            mock_logger.info.assert_not_called()

    def test_log_handles_exception(self) -> None:
        DiscoveryState.controller_count = 1
        DiscoveryState.controllers_by_domain = {"d": ["C"]}

        with patch("app.utils.domain._state.logger") as mock_logger:
            mock_logger.info.side_effect = [Exception("format error"), None]
            DiscoveryState.log_discovery_results()
            assert mock_logger.info.call_count == 2
            assert DiscoveryState.logged_controllers is True
