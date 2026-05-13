"""Tests for env utility functions."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from app.utils.env import (
    TRUE_VALUES,
    _parse_dict,
    _parse_dict_comma,
    _parse_dict_json,
    _parse_list,
    get_config_val,
    get_env,
    is_typed_dict,
)


class TestGetConfigValBasic:
    def test_string_default(self) -> None:
        with patch.dict(os.environ, {"STR_VAL": "hello"}):
            assert get_config_val("STR_VAL", default="") == "hello"

    def test_int_default(self) -> None:
        with patch.dict(os.environ, {"INT_VAL": "123"}):
            assert get_config_val("INT_VAL", default=0) == 123

    def test_bool_true_values(self) -> None:
        for val in TRUE_VALUES:
            with patch.dict(os.environ, {"BOOL_VAL": val}):
                assert get_config_val("BOOL_VAL", default=False) is True

    def test_bool_false_value(self) -> None:
        with patch.dict(os.environ, {"BOOL_VAL": "false"}):
            assert get_config_val("BOOL_VAL", default=False) is False

    def test_missing_returns_default(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            assert get_config_val("DEFINITELY_MISSING_KEY_12345", default="default") == "default"

    def test_none_default(self) -> None:
        with patch.dict(os.environ, {"NONE_VAL": "something"}):
            result = get_config_val("NONE_VAL", default=None)
            assert result == "something"

    def test_none_default_missing(self) -> None:
        assert get_config_val("DEFINITELY_MISSING_KEY_12345", default=None) is None


class TestGetConfigValPath:
    def test_path_from_default_type(self) -> None:
        with patch.dict(os.environ, {"PATH_VAL": "/tmp/test"}):
            result = get_config_val("PATH_VAL", default=Path("/tmp"))
            assert isinstance(result, Path)
            assert str(result) == "/tmp/test"

    def test_path_list_from_type_hint(self) -> None:
        with patch.dict(os.environ, {"PATH_LIST": "/a,/b,/c"}):
            result = get_config_val("PATH_LIST", default=[], type_hint=list[Path])
            assert all(isinstance(p, Path) for p in result)
            assert [str(p) for p in result] == ["/a", "/b", "/c"]

    def test_path_list_json(self) -> None:
        with patch.dict(os.environ, {"PATH_LIST": '["/a", "/b"]'}):
            result = get_config_val("PATH_LIST", default=[], type_hint=list[Path])
            assert all(isinstance(p, Path) for p in result)
            assert [str(p) for p in result] == ["/a", "/b"]


class TestGetConfigValList:
    def test_list_json_str(self) -> None:
        with patch.dict(os.environ, {"LIST_VAL": '["a", "b", "c"]'}):
            result = get_config_val("LIST_VAL", default=[], type_hint=list[str])
            assert result == ["a", "b", "c"]

    def test_list_comma_str(self) -> None:
        with patch.dict(os.environ, {"LIST_VAL": "a,b,c"}):
            result = get_config_val("LIST_VAL", default=[], type_hint=list[str])
            assert result == ["a", "b", "c"]

    def test_list_from_default_type_str(self) -> None:
        with patch.dict(os.environ, {"LIST_VAL": "x,y"}):
            result = get_config_val("LIST_VAL", default=["a"])
            assert result == ["x", "y"]

    def test_list_from_default_type_path(self) -> None:
        with patch.dict(os.environ, {"LIST_VAL": "/x,/y"}):
            result = get_config_val("LIST_VAL", default=[Path("/a")])
            assert all(isinstance(p, Path) for p in result)

    def test_invalid_list_bracket_no_close(self) -> None:
        with (
            patch.dict(os.environ, {"BAD": "[a,b"}),
            pytest.raises(ValueError, match="not a valid list representation"),
        ):
            get_config_val("BAD", default=[], type_hint=list[str])

    def test_json_array_of_non_list(self) -> None:
        # Starts with '[' but json.loads returns something that isn't a list? Not possible
        # with valid JSON arrays. Test bracket mismatch instead.
        with pytest.raises(ValueError, match="not a valid list representation"):
            _parse_list("BAD", "[invalid json", str)

    def test_unsupported_item_type(self) -> None:
        with (
            patch.dict(os.environ, {"BAD": "1,2"}),
            pytest.raises(ValueError, match="Unsupported item type"),
        ):
            get_config_val("BAD", default=[], type_hint=list[int])


class TestGetConfigValDict:
    def test_dict_json(self) -> None:
        with patch.dict(os.environ, {"DICT_VAL": '{"a": 1, "b": 2}'}):
            result = get_config_val("DICT_VAL", default={}, type_hint=dict[str, str])
            assert result == {"a": "1", "b": "2"}

    def test_dict_comma(self) -> None:
        with patch.dict(os.environ, {"DICT_VAL": "a=1,b=2"}):
            result = get_config_val("DICT_VAL", default={}, type_hint=dict[str, str])
            assert result == {"a": "1", "b": "2"}

    def test_dict_from_default(self) -> None:
        with patch.dict(os.environ, {"DICT_VAL": "x=1"}):
            result = get_config_val("DICT_VAL", default={"a": "b"})
            assert result == {"x": "1"}

    def test_invalid_dict_comma_no_equals(self) -> None:
        with (
            patch.dict(os.environ, {"BAD": "a"}),
            pytest.raises(TypeError, match="not a valid dict representation"),
        ):
            get_config_val("BAD", default={}, type_hint=dict[str, str])

    def test_invalid_dict_json_malformed(self) -> None:
        with pytest.raises(TypeError, match="not a valid dict representation"):
            _parse_dict_json("BAD", "{malformed")

    def test_invalid_dict_json_not_dict(self) -> None:
        with pytest.raises(TypeError, match="not a valid dict representation"):
            _parse_dict_json("BAD", '["not", "a", "dict"]')

    def test_dict_comma_skips_empty(self) -> None:
        result = _parse_dict_comma("K", "a=1,,b=2,")
        assert result == {"a": "1", "b": "2"}


class TestGetEnv:
    def test_returns_callable(self) -> None:
        factory = get_env("MISSING_VAL_FOR_TEST", "fallback")
        assert callable(factory)
        assert factory() == "fallback"

    def test_callable_reads_env(self) -> None:
        factory = get_env("DYNAMIC_VAL", "default")
        with patch.dict(os.environ, {"DYNAMIC_VAL": "live"}):
            assert factory() == "live"


class TestParseList:
    def test_json_format(self) -> None:
        result = _parse_list("K", '["a", "b"]', str)
        assert result == ["a", "b"]

    def test_comma_format(self) -> None:
        result = _parse_list("K", "a, b, c", str)
        assert result == ["a", "b", "c"]

    def test_path_items(self) -> None:
        result = _parse_list("K", "/a,/b", Path)
        assert all(isinstance(p, Path) for p in result)

    def test_json_item_conversion_error(self) -> None:
        with pytest.raises(ValueError, match="not a valid list representation"):
            _parse_list("K", '["not_a_number"]', int)


class TestParseDict:
    def test_json_detected(self) -> None:
        result = _parse_dict("K", '{"x": "1"}')
        assert result == {"x": "1"}

    def test_comma_detected(self) -> None:
        result = _parse_dict("K", "x=1,y=2")
        assert result == {"x": "1", "y": "2"}


class TestIsTypedDict:
    def test_regular_dict_false(self) -> None:
        assert is_typed_dict(dict) is False

    def test_str_false(self) -> None:
        assert is_typed_dict(str) is False

    def test_none_false(self) -> None:
        assert is_typed_dict(None) is False

    def test_non_type_false(self) -> None:
        assert is_typed_dict(42) is False


class TestGetConfigValTypeHint:
    def test_type_hint_as_concrete_type(self) -> None:
        with patch.dict(os.environ, {"VAL": "42"}):
            result = get_config_val("VAL", default=None, type_hint=int)
            assert result == 42

    def test_type_hint_bool(self) -> None:
        with patch.dict(os.environ, {"VAL": "true"}):
            result = get_config_val("VAL", default=None, type_hint=bool)
            assert result is True

    def test_type_hint_path(self) -> None:
        with patch.dict(os.environ, {"VAL": "/tmp/x"}):
            result = get_config_val("VAL", default=None, type_hint=Path)
            assert isinstance(result, Path)

    def test_type_hint_str(self) -> None:
        with patch.dict(os.environ, {"VAL": "hello"}):
            result = get_config_val("VAL", default=None, type_hint=str)
            assert result == "hello"
