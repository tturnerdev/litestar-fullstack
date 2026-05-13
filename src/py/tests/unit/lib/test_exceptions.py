from typing import TYPE_CHECKING, cast
from unittest.mock import MagicMock, patch

import pytest
from advanced_alchemy.exceptions import DuplicateKeyError, IntegrityError
from litestar.exceptions import (
    ClientException,
    InternalServerException,
    NotFoundException,
    PermissionDeniedException,
)
from litestar.repository.exceptions import ConflictError, NotFoundError

from app.lib.exceptions import (
    ApplicationClientError,
    ApplicationError,
    AuthorizationError,
    HealthCheckConfigurationError,
    MissingDependencyError,
    _HTTPConflictException,
    after_exception_hook_handler,
    exception_to_http_response,
)

if TYPE_CHECKING:
    from litestar.types import Scope

pytestmark = pytest.mark.anyio


class TestApplicationError:
    def test_init_with_detail(self) -> None:
        exc = ApplicationError("msg", detail="detailed info")
        assert exc.detail == "detailed info"
        assert "msg" in str(exc)
        assert "detailed info" in str(exc)

    def test_init_detail_from_first_arg(self) -> None:
        exc = ApplicationError("msg")
        assert exc.detail == "msg"

    def test_init_no_args(self) -> None:
        exc = ApplicationError()
        assert exc.detail == ""

    def test_repr_with_detail(self) -> None:
        exc = ApplicationError(detail="info")
        assert "ApplicationError - info" in repr(exc)

    def test_repr_without_detail(self) -> None:
        exc = ApplicationError()
        assert repr(exc) == "ApplicationError"


class TestExceptionSubclasses:
    def test_missing_dependency_is_import_error(self) -> None:
        exc = MissingDependencyError("pkg")
        assert isinstance(exc, ApplicationError)
        assert isinstance(exc, ImportError)

    def test_client_error(self) -> None:
        exc = ApplicationClientError("bad input")
        assert isinstance(exc, ApplicationError)
        assert exc.detail == "bad input"

    def test_authorization_error(self) -> None:
        exc = AuthorizationError("forbidden")
        assert isinstance(exc, ApplicationClientError)

    def test_health_check_error(self) -> None:
        exc = HealthCheckConfigurationError("bad config")
        assert isinstance(exc, ApplicationError)

    def test_http_conflict_status(self) -> None:
        assert _HTTPConflictException.status_code == 409


class TestAfterExceptionHookHandler:
    def test_ignores_application_error(self) -> None:
        exc = ApplicationError("test")
        scope = cast("Scope", {})
        with patch("app.lib.exceptions.bind_contextvars") as mock_bind:
            after_exception_hook_handler(exc, scope)
            mock_bind.assert_not_called()

    def test_ignores_client_http_exception(self) -> None:
        exc = ClientException(detail="bad request")
        scope = cast("Scope", {})
        with patch("app.lib.exceptions.bind_contextvars") as mock_bind:
            after_exception_hook_handler(exc, scope)
            mock_bind.assert_not_called()

    def test_binds_for_server_error(self) -> None:
        exc = ValueError("test")
        scope = cast("Scope", {})
        with patch("app.lib.exceptions.bind_contextvars") as mock_bind:
            after_exception_hook_handler(exc, scope)
            mock_bind.assert_called_once()

    def test_binds_for_500_http_exception(self) -> None:
        exc = InternalServerException(detail="server error")
        scope = cast("Scope", {})
        with patch("app.lib.exceptions.bind_contextvars") as mock_bind:
            after_exception_hook_handler(exc, scope)
            mock_bind.assert_called_once()


class TestExceptionToHttpResponse:
    def _make_request(self, debug: bool = False) -> MagicMock:
        request = MagicMock()
        request.app.debug = debug
        return request

    async def test_not_found_error(self) -> None:
        exc = NotFoundError("not found")
        with patch("app.lib.exceptions.create_exception_response") as mock_create:
            exception_to_http_response(self._make_request(), exc)
            args, _ = mock_create.call_args
            assert isinstance(args[1], NotFoundException)

    async def test_conflict_error(self) -> None:
        exc = ConflictError("conflict")
        with patch("app.lib.exceptions.create_exception_response") as mock_create:
            exception_to_http_response(self._make_request(), exc)
            args, _ = mock_create.call_args
            assert isinstance(args[1], _HTTPConflictException)

    async def test_integrity_error(self) -> None:
        exc = IntegrityError("dup")
        with patch("app.lib.exceptions.create_exception_response") as mock_create:
            exception_to_http_response(self._make_request(), exc)
            args, _ = mock_create.call_args
            assert isinstance(args[1], _HTTPConflictException)

    async def test_duplicate_key_error(self) -> None:
        exc = DuplicateKeyError("dup key")
        with patch("app.lib.exceptions.create_exception_response") as mock_create:
            exception_to_http_response(self._make_request(), exc)
            args, _ = mock_create.call_args
            assert isinstance(args[1], _HTTPConflictException)

    async def test_authorization_error(self) -> None:
        exc = AuthorizationError("unauthorized")
        with patch("app.lib.exceptions.create_exception_response") as mock_create:
            exception_to_http_response(self._make_request(), exc)
            args, _ = mock_create.call_args
            assert isinstance(args[1], PermissionDeniedException)

    async def test_client_error(self) -> None:
        exc = ApplicationClientError("bad input")
        with patch("app.lib.exceptions.create_exception_response") as mock_create:
            exception_to_http_response(self._make_request(), exc)
            args, _ = mock_create.call_args
            assert isinstance(args[1], ClientException)

    async def test_generic_error_maps_to_internal(self) -> None:
        exc = RuntimeError("boom")
        with patch("app.lib.exceptions.create_exception_response") as mock_create:
            exception_to_http_response(self._make_request(), exc)
            args, _ = mock_create.call_args
            assert isinstance(args[1], InternalServerException)

    async def test_debug_mode_generic_error(self) -> None:
        exc = ValueError("internal error")
        with patch("app.lib.exceptions.create_debug_response") as mock_debug:
            exception_to_http_response(self._make_request(debug=True), exc)
            mock_debug.assert_called_once()

    async def test_debug_mode_skips_debug_for_permission(self) -> None:
        exc = AuthorizationError("nope")
        with patch("app.lib.exceptions.create_exception_response") as mock_create:
            exception_to_http_response(self._make_request(debug=True), exc)
            args, _ = mock_create.call_args
            assert isinstance(args[1], PermissionDeniedException)

    async def test_detail_from_cause(self) -> None:
        cause = RuntimeError("root cause")
        exc = RuntimeError("wrapper")
        exc.__cause__ = cause
        with patch("app.lib.exceptions.create_exception_response") as mock_create:
            exception_to_http_response(self._make_request(), exc)
            args, _ = mock_create.call_args
            assert "root cause" in args[1].detail
