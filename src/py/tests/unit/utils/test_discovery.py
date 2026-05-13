"""Tests for domain discovery logic."""

from __future__ import annotations

from typing import cast
from unittest.mock import MagicMock, patch

from litestar import Controller

from app.utils.domain import _discovery as discovery


class TestFindControllersInModule:
    def test_finds_controller_subclass(self) -> None:
        import types

        class FakeController(Controller):
            pass

        module = types.ModuleType("test_module")
        module.FakeController = FakeController  # type: ignore[attr-defined]
        FakeController.__module__ = "test_module"

        result = discovery.find_controllers_in_module(module)
        assert FakeController in result

    def test_skips_base_controller(self) -> None:
        import types

        module = types.ModuleType("test_module")
        module.Controller = Controller  # type: ignore[attr-defined]

        result = discovery.find_controllers_in_module(module)
        assert result == []

    def test_skips_non_controller(self) -> None:
        import types

        module = types.ModuleType("test_module")

        class NotAController:
            pass

        NotAController.__module__ = "test_module"
        module.NotAController = NotAController  # type: ignore[attr-defined]

        result = discovery.find_controllers_in_module(module)
        assert result == []

    def test_skips_imported_controller(self) -> None:
        import types

        class FakeController(Controller):
            pass

        FakeController.__module__ = "other_module"
        module = types.ModuleType("test_module")
        module.FakeController = FakeController  # type: ignore[attr-defined]

        result = discovery.find_controllers_in_module(module)
        assert result == []

    def test_skips_private_controller(self) -> None:
        import types

        class _PrivateController(Controller):
            pass

        _PrivateController.__module__ = "test_module"
        module = types.ModuleType("test_module")
        module._PrivateController = _PrivateController  # type: ignore[attr-defined]

        result = discovery.find_controllers_in_module(module)
        assert result == []


class TestIterDomainDirectories:
    def test_import_error_returns_empty(self) -> None:
        with patch("importlib.import_module", side_effect=ImportError):
            result = discovery._iter_domain_directories("nonexistent.pkg")
            assert result == []

    def test_no_path_attr_returns_empty(self) -> None:
        mock_module = MagicMock(spec=[])
        with patch("importlib.import_module", return_value=mock_module):
            result = discovery._iter_domain_directories("pkg")
            assert result == []


class TestDiscoverModulesExports:
    def test_skips_import_errors(self) -> None:
        with (
            patch("app.utils.domain._discovery._iter_submodules", return_value=["bad.module"]),
            patch("importlib.import_module", side_effect=ImportError),
        ):
            result = list(discovery._discover_modules_exports(["pkg"], ["sub"]))
            assert result == []

    def test_skips_modules_without_all(self) -> None:
        mock_module = MagicMock(spec=[])
        with (
            patch("app.utils.domain._discovery._iter_submodules", return_value=["pkg.sub"]),
            patch("importlib.import_module", return_value=mock_module),
        ):
            result = list(discovery._discover_modules_exports(["pkg"], ["sub"]))
            assert result == []


class TestDiscoverDomainSchemas:
    def test_discovers_schemas(self) -> None:
        mock_module = MagicMock()
        mock_module.__all__ = ["SchemaA", "SchemaB"]
        mock_module.SchemaA = "SchemaA_Obj"
        mock_module.SchemaB = "SchemaB_Obj"

        with (
            patch("app.utils.domain._discovery._iter_submodules", return_value=["pkg.sub"]),
            patch("importlib.import_module", return_value=mock_module) as mock_import,
        ):
            schemas = discovery.discover_domain_schemas(["pkg"])
            assert schemas == {"SchemaA": "SchemaA_Obj", "SchemaB": "SchemaB_Obj"}
            mock_import.assert_called_with("pkg.sub")

    def test_default_submodules(self) -> None:
        with (
            patch("app.utils.domain._discovery._iter_submodules", return_value=[]) as mock_iter,
            patch("importlib.import_module"),
        ):
            discovery.discover_domain_schemas(["pkg"])
            mock_iter.assert_called_once_with(["pkg"], ["schemas", "models", "dtos"])


class TestDiscoverDomainServices:
    def test_discovers_services(self) -> None:
        mock_module = MagicMock()
        mock_module.__all__ = ["ServiceA"]
        mock_module.ServiceA = "ServiceA_Obj"

        with (
            patch("app.utils.domain._discovery._iter_submodules", return_value=["pkg.sub"]),
            patch("importlib.import_module", return_value=mock_module),
        ):
            services = discovery.discover_domain_services(["pkg"])
            assert services == {"ServiceA": "ServiceA_Obj"}

    def test_default_submodules(self) -> None:
        with (
            patch("app.utils.domain._discovery._iter_submodules", return_value=[]) as mock_iter,
            patch("importlib.import_module"),
        ):
            discovery.discover_domain_services(["pkg"])
            mock_iter.assert_called_once_with(["pkg"], ["services"])


class TestDiscoverDomainSignals:
    def test_discovers_signals(self) -> None:
        mock_module = MagicMock()
        mock_module.__all__ = ["SignalA"]
        mock_module.SignalA = "SignalA_Obj"

        with (
            patch("app.utils.domain._discovery._iter_submodules", return_value=["pkg.sub"]),
            patch("importlib.import_module", return_value=mock_module),
        ):
            signals = discovery.discover_domain_signals(["pkg"])
            assert cast("list[str]", signals) == ["SignalA_Obj"]

    def test_default_submodules(self) -> None:
        with (
            patch("app.utils.domain._discovery._iter_submodules", return_value=[]) as mock_iter,
            patch("importlib.import_module"),
        ):
            discovery.discover_domain_signals(["pkg"])
            mock_iter.assert_called_once_with(["pkg"], ["signals", "events", "listeners"])


class TestDiscoverDomainRepositories:
    def test_discovers_repositories(self) -> None:
        mock_module = MagicMock()
        mock_module.__all__ = ["RepoA"]
        mock_module.RepoA = "RepoA_Obj"

        with (
            patch("app.utils.domain._discovery._iter_submodules", return_value=["pkg.sub"]),
            patch("importlib.import_module", return_value=mock_module),
        ):
            repos = discovery.discover_domain_repositories(["pkg"])
            assert repos == {"RepoA": "RepoA_Obj"}

    def test_default_submodules(self) -> None:
        with (
            patch("app.utils.domain._discovery._iter_submodules", return_value=[]) as mock_iter,
            patch("importlib.import_module"),
        ):
            discovery.discover_domain_repositories(["pkg"])
            mock_iter.assert_called_once_with(["pkg"], ["repositories", "repos"])


class TestDiscoverDomainControllers:
    def test_uses_cache(self) -> None:
        from app.utils.domain._state import cache

        cached = [MagicMock()]
        cache.set(cached, ["pkg"])  # type: ignore[arg-type]
        try:
            result = discovery.discover_domain_controllers(["pkg"])
            assert result == cached
        finally:
            cache.clear()

    def test_deduplicates(self) -> None:
        from app.utils.domain._state import cache

        cache.clear()

        class FakeCtrl(Controller):
            pass

        FakeCtrl.__module__ = "app.domain.test.controllers._fake"

        with patch(
            "app.utils.domain._discovery._discover_controllers_in_submodule",
            return_value=[FakeCtrl, FakeCtrl],
        ), patch("app.utils.domain._discovery._iter_submodules", return_value=["pkg.sub"]):
            result = discovery.discover_domain_controllers(["pkg"])
            assert len(result) == 1
            cache.clear()


class TestDiscoverControllersInSubmodule:
    def test_import_error_returns_empty(self) -> None:
        with patch("importlib.import_module", side_effect=ImportError):
            result = discovery._discover_controllers_in_submodule("bad.path")
            assert result == []

    def test_simple_module(self) -> None:
        class FakeCtrl(Controller):
            pass

        FakeCtrl.__module__ = "pkg.controllers"
        mock_module = MagicMock(spec=["__name__"])
        mock_module.__name__ = "pkg.controllers"

        with (
            patch("importlib.import_module", return_value=mock_module),
            patch.object(discovery, "find_controllers_in_module", return_value=[FakeCtrl]),
        ):
            result = discovery._discover_controllers_in_submodule("pkg.controllers")
            assert FakeCtrl in result
