"""Tests for domain discovery plugin."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.utils.domain._config import DomainPluginConfig
from app.utils.domain._plugin import DomainPlugin, _on_startup_log_discovery
from app.utils.domain._state import DiscoveryState


class TestDomainPluginConfig:
    def test_defaults(self) -> None:
        config = DomainPluginConfig()
        assert config.domain_packages == ["app.domain"]
        assert config.discover_controllers is True
        assert config.discover_signals is True
        assert config.discover_schemas is True
        assert config.discover_services is True
        assert config.discover_repositories is True
        assert config.log_discovered is True

    def test_custom_packages(self) -> None:
        config = DomainPluginConfig(domain_packages=["custom.domain"])
        assert config.domain_packages == ["custom.domain"]


class TestDomainPlugin:
    def test_default_config(self) -> None:
        plugin = DomainPlugin()
        assert plugin.config.domain_packages == ["app.domain"]

    def test_custom_config(self) -> None:
        config = DomainPluginConfig(discover_controllers=False)
        plugin = DomainPlugin(config=config)
        assert plugin.config.discover_controllers is False

    def test_on_app_init_discovers_controllers(self) -> None:
        from litestar import Controller

        class FakeCtrl(Controller):
            pass

        FakeCtrl.__module__ = "app.domain.test.controllers._fake"
        config = DomainPluginConfig(
            discover_controllers=True,
            discover_signals=False,
            discover_schemas=False,
            discover_services=False,
            discover_repositories=False,
            log_discovered=False,
        )
        plugin = DomainPlugin(config=config)
        app_config = MagicMock()
        app_config.route_handlers = []

        with patch(
            "app.utils.domain._plugin.discover_domain_controllers",
            return_value=[FakeCtrl],
        ):
            result = plugin.on_app_init(app_config)

        assert FakeCtrl in result.route_handlers

    def test_on_app_init_no_controllers_warns(self) -> None:
        config = DomainPluginConfig(
            discover_controllers=True,
            discover_signals=False,
            discover_schemas=False,
            discover_services=False,
            discover_repositories=False,
            log_discovered=False,
        )
        plugin = DomainPlugin(config=config)
        app_config = MagicMock()
        app_config.route_handlers = []

        with (
            patch("app.utils.domain._plugin.discover_domain_controllers", return_value=[]),
            patch("app.utils.domain._plugin.logger") as mock_logger,
        ):
            plugin.on_app_init(app_config)
            mock_logger.warning.assert_called_once()

    def test_on_app_init_discovers_signals(self) -> None:
        config = DomainPluginConfig(
            discover_controllers=False,
            discover_signals=True,
            discover_schemas=False,
            discover_services=False,
            discover_repositories=False,
            log_discovered=False,
        )
        plugin = DomainPlugin(config=config)
        app_config = MagicMock()
        app_config.listeners = []

        mock_signal = MagicMock()
        with patch("app.utils.domain._plugin.discover_domain_signals", return_value=[mock_signal]):
            plugin.on_app_init(app_config)
            assert mock_signal in app_config.listeners

    def test_on_app_init_discovers_schemas(self) -> None:
        config = DomainPluginConfig(
            discover_controllers=False,
            discover_signals=False,
            discover_schemas=True,
            discover_services=False,
            discover_repositories=False,
            log_discovered=False,
        )
        plugin = DomainPlugin(config=config)
        app_config = MagicMock()
        app_config.signature_namespace = {}

        with patch("app.utils.domain._plugin.discover_domain_schemas", return_value={"S": "obj"}):
            plugin.on_app_init(app_config)
            assert app_config.signature_namespace["S"] == "obj"

    def test_on_app_init_discovers_services(self) -> None:
        config = DomainPluginConfig(
            discover_controllers=False,
            discover_signals=False,
            discover_schemas=False,
            discover_services=True,
            discover_repositories=False,
            log_discovered=False,
        )
        plugin = DomainPlugin(config=config)
        app_config = MagicMock()
        app_config.signature_namespace = {}

        with patch("app.utils.domain._plugin.discover_domain_services", return_value={"Svc": "obj"}):
            plugin.on_app_init(app_config)
            assert app_config.signature_namespace["Svc"] == "obj"

    def test_on_app_init_discovers_repositories(self) -> None:
        config = DomainPluginConfig(
            discover_controllers=False,
            discover_signals=False,
            discover_schemas=False,
            discover_services=False,
            discover_repositories=True,
            log_discovered=False,
        )
        plugin = DomainPlugin(config=config)
        app_config = MagicMock()
        app_config.signature_namespace = {}

        with patch("app.utils.domain._plugin.discover_domain_repositories", return_value={"Repo": "obj"}):
            plugin.on_app_init(app_config)
            assert app_config.signature_namespace["Repo"] == "obj"

    def test_on_app_init_registers_startup_hook(self) -> None:
        config = DomainPluginConfig(
            discover_controllers=False,
            discover_signals=False,
            discover_schemas=False,
            discover_services=False,
            discover_repositories=False,
            log_discovered=True,
        )
        plugin = DomainPlugin(config=config)
        app_config = MagicMock()
        app_config.on_startup = None

        plugin.on_app_init(app_config)
        assert app_config.on_startup is not None
        assert _on_startup_log_discovery in app_config.on_startup

    def test_store_controller_results(self) -> None:
        from litestar import Controller

        DiscoveryState.reset()

        class FakeCtrl(Controller):
            pass

        FakeCtrl.__module__ = "app.domain.accounts.controllers._user"

        plugin = DomainPlugin()
        plugin._store_controller_results([FakeCtrl])

        assert DiscoveryState.controller_count == 1
        assert "accounts" in DiscoveryState.controllers_by_domain
        assert "FakeCtrl" in DiscoveryState.controllers_by_domain["accounts"]

    def test_store_controller_unknown_domain(self) -> None:
        from litestar import Controller

        DiscoveryState.reset()

        class WeirdCtrl(Controller):
            pass

        WeirdCtrl.__module__ = "some.other.module"

        plugin = DomainPlugin()
        plugin._store_controller_results([WeirdCtrl])

        assert DiscoveryState.controller_count == 1
        assert "unknown" in DiscoveryState.controllers_by_domain


class TestOnStartupLogDiscovery:
    def test_delegates_to_state(self) -> None:
        DiscoveryState.reset()
        DiscoveryState.controller_count = 1
        DiscoveryState.controllers_by_domain = {"test": ["Ctrl"]}

        with patch("app.utils.domain._state.logger"):
            _on_startup_log_discovery()
            assert DiscoveryState.logged_controllers is True
