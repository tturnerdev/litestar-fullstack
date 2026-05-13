"""Tests for webhook domain schema validation."""

from __future__ import annotations

import msgspec
import pytest

from app.domain.webhooks.schemas._webhook import WebhookCreate, WebhookUpdate
from app.domain.webhooks.schemas._webhook_endpoint import WebhookEndpointCreate, WebhookEndpointUpdate
from app.lib.validation import ValidationError


class TestWebhookCreate:
    def test_valid(self) -> None:
        w = WebhookCreate(name="My Hook", url="https://example.com/hook")
        assert w.url == "https://example.com/hook"

    def test_invalid_url(self) -> None:
        with pytest.raises(ValidationError):
            WebhookCreate(name="Bad", url="not-a-url")

    def test_localhost_blocked(self) -> None:
        with pytest.raises(ValidationError, match="domain not allowed"):
            WebhookCreate(name="Local", url="https://localhost/hook")


class TestWebhookUpdate:
    def test_validates_url_when_set(self) -> None:
        u = WebhookUpdate(url="https://example.com/new")
        assert u.url == "https://example.com/new"

    def test_invalid_url(self) -> None:
        with pytest.raises(ValidationError):
            WebhookUpdate(url="bad")

    def test_skips_validation_when_unset(self) -> None:
        u = WebhookUpdate(name="Renamed")
        assert u.url is msgspec.UNSET


class TestWebhookEndpointCreate:
    def test_valid(self) -> None:
        e = WebhookEndpointCreate(url="https://example.com/endpoint")
        assert e.url == "https://example.com/endpoint"

    def test_invalid_url(self) -> None:
        with pytest.raises(ValidationError):
            WebhookEndpointCreate(url="ftp://bad.com")


class TestWebhookEndpointUpdate:
    def test_validates_url_when_set(self) -> None:
        u = WebhookEndpointUpdate(url="https://example.com/updated")
        assert u.url == "https://example.com/updated"

    def test_skips_validation_when_unset(self) -> None:
        u = WebhookEndpointUpdate(is_active=False)
        assert u.url is msgspec.UNSET
